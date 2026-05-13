import os
import logging
import time
from typing import List, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget,
    QToolBar, QAction, QStatusBar, QLabel,
    QFileDialog, QMessageBox, QProgressDialog, QApplication,
    QToolButton, QMenu, QSizePolicy,
)
from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette

from ..core.pcap_loader import PCAPLoader
from ..core.ddos_detector import DDoSDetector
from ..core.tshark_capture import TSharkCapture, find_tshark
from ..core.models import PacketInfo, Alert, NetworkStats
from .widgets.dashboard_tab import DashboardTab
from .widgets.packets_tab import PacketsTab
from .widgets.analysis_tab import AnalysisTab
from .widgets.capture_dialog import CaptureDialog
from .styles import APP_STYLESHEET, DARK

logger = logging.getLogger(__name__)

# How often (ms) to flush the live-capture buffer → update UI
_LIVE_FLUSH_INTERVAL_MS = 800


# ── PCAP load worker ──────────────────────────────────────────────────────────

class LoadWorker(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(list, list, object)   # packets, alerts, stats
    error    = pyqtSignal(str)

    def __init__(self, filepath: str):
        super().__init__()
        self.filepath = filepath

    def run(self):
        try:
            loader = PCAPLoader()
            packets = loader.load(self.filepath, progress_cb=self.progress.emit)
            detector = DDoSDetector()
            alerts, stats = detector.analyze(packets)
            self.finished.emit(packets, alerts, stats)
        except Exception as exc:
            self.error.emit(str(exc))


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.packets: List[PacketInfo] = []
        self.alerts:  List[Alert]      = []
        self.stats:   Optional[NetworkStats] = None

        self._load_worker:    Optional[LoadWorker]    = None
        self._capture_worker: Optional[TSharkCapture] = None

        # Buffer for live packets between flush ticks
        self._live_buffer: List[PacketInfo] = []
        self._live_start_ts: float = 0.0

        # QTimer drives periodic UI refresh during live capture
        self._live_timer = QTimer(self)
        self._live_timer.setInterval(_LIVE_FLUSH_INTERVAL_MS)
        self._live_timer.timeout.connect(self._flush_live_buffer)

        self.setWindowTitle("DDoS Analyzer  —  Network Security Monitor")
        self.setMinimumSize(1200, 720)
        self.resize(1440, 900)
        self.setStyleSheet(APP_STYLESHEET)

        self._build_ui()
        self._build_toolbar()
        self._build_statusbar()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.dashboard   = DashboardTab()
        self.packets_tab = PacketsTab()
        self.analysis    = AnalysisTab()

        self.tabs.addTab(self.dashboard,   "  Dashboard  ")
        self.tabs.addTab(self.packets_tab, "  Packets  ")
        self.tabs.addTab(self.analysis,    "  Phân Tích DDoS  ")

        layout.addWidget(self.tabs)

    def _build_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        self.addToolBar(tb)

        # Open PCAP ─────────────────────────────────────────────────────────
        self.act_open = QAction("📂  Mở File PCAP", self)
        self.act_open.setShortcut("Ctrl+O")
        self.act_open.setToolTip("Ctrl+O — Mở file .pcap / .pcapng")
        self.act_open.triggered.connect(self.open_pcap)
        tb.addAction(self.act_open)

        tb.addSeparator()

        # Live Capture ───────────────────────────────────────────────────────
        self.act_live = QAction("🔴  Live Capture", self)
        self.act_live.setToolTip("Bắt đầu capture real-time qua TShark")
        self.act_live.triggered.connect(self.start_live_capture)
        tb.addAction(self.act_live)

        self.act_stop = QAction("⏹  Dừng", self)
        self.act_stop.setToolTip("Dừng live capture")
        self.act_stop.triggered.connect(self.stop_live_capture)
        self.act_stop.setEnabled(False)
        tb.addAction(self.act_stop)

        tb.addSeparator()

        # Re-analyze ────────────────────────────────────────────────────────
        self.act_reanalyze = QAction("🔍  Phân Tích Lại", self)
        self.act_reanalyze.setToolTip("Chạy lại thuật toán phát hiện DDoS")
        self.act_reanalyze.triggered.connect(self.reanalyze)
        self.act_reanalyze.setEnabled(False)
        tb.addAction(self.act_reanalyze)

        tb.addSeparator()

        # Suspicious only ───────────────────────────────────────────────────
        self.act_suspicious = QAction("⚠  Chỉ Gói Nghi Ngờ", self)
        self.act_suspicious.setCheckable(True)
        self.act_suspicious.toggled.connect(self._toggle_suspicious)
        self.act_suspicious.setEnabled(False)
        tb.addAction(self.act_suspicious)

        tb.addSeparator()

        act_about = QAction("ℹ  Về Phần Mềm", self)
        act_about.triggered.connect(self._show_about)
        tb.addAction(act_about)

        # Spacer + file label ────────────────────────────────────────────────
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)

        self.file_lbl = QLabel("Chưa mở file")
        self.file_lbl.setStyleSheet(
            f"color: {DARK['muted']}; font-size: 12px; padding-right: 12px;"
        )
        tb.addWidget(self.file_lbl)

    def _build_statusbar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status_lbl = QLabel("Sẵn sàng  —  Mở file PCAP hoặc bắt đầu Live Capture")
        sb.addWidget(self.status_lbl, 1)

        # Live indicator on the right of status bar
        self.live_badge = QLabel()
        self.live_badge.setVisible(False)
        self.live_badge.setStyleSheet(
            f"background-color: {DARK['red']}; color: white;"
            f"font-weight: 700; padding: 2px 10px; border-radius: 4px;"
        )
        sb.addPermanentWidget(self.live_badge)

    # ── PCAP file loading ─────────────────────────────────────────────────────

    def open_pcap(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Mở File PCAP", "",
            "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if filepath:
            self._load_file(filepath)

    def _load_file(self, filepath: str):
        self.status_lbl.setText(f"Đang tải:  {os.path.basename(filepath)} …")
        self.act_open.setEnabled(False)
        self.act_live.setEnabled(False)

        self._progress = QProgressDialog(
            "Đang đọc và phân tích file PCAP…", "Hủy", 0, 100, self
        )
        self._progress.setWindowTitle("Vui lòng chờ")
        self._progress.setWindowModality(Qt.WindowModal)
        self._progress.setMinimumWidth(380)
        self._progress.show()

        self._load_worker = LoadWorker(filepath)
        self._load_worker.progress.connect(self._on_load_progress)
        self._load_worker.finished.connect(self._on_loaded)
        self._load_worker.error.connect(self._on_load_error)
        self._progress.canceled.connect(self._load_worker.terminate)
        self._load_worker.start()

    def _on_load_progress(self, current: int, total: int):
        if total > 0:
            self._progress.setValue(int(current * 100 / total))

    def _on_loaded(self, packets, alerts, stats):
        self._progress.close()
        self.act_open.setEnabled(True)
        self.act_live.setEnabled(True)
        self.packets = packets
        self.alerts  = alerts
        self.stats   = stats

        filename = os.path.basename(self._load_worker.filepath) if self._load_worker else ""
        self.file_lbl.setText(filename)
        self.dashboard.update_data(packets, alerts, stats)
        self.packets_tab.update_packets(packets)
        self.analysis.update_alerts(alerts, stats)
        self.act_reanalyze.setEnabled(True)
        self.act_suspicious.setEnabled(True)

        sev_text = ""
        if alerts:
            sev_text = f"  |  ⚠ {len(alerts)} cảnh báo — mức cao nhất: {alerts[0].severity.value}"
        self.status_lbl.setText(
            f"{len(packets):,} packets  |  {stats.duration:.1f}s  "
            f"|  {stats.avg_bandwidth_mbps:.2f} MB/s{sev_text}"
        )
        self.tabs.setCurrentIndex(0)

    def _on_load_error(self, msg: str):
        self._progress.close()
        self.act_open.setEnabled(True)
        self.act_live.setEnabled(True)
        QMessageBox.critical(self, "Lỗi tải file", msg)
        self.status_lbl.setText("Lỗi — không thể tải file.")

    # ── Live Capture ──────────────────────────────────────────────────────────

    def start_live_capture(self):
        tshark = find_tshark()

        dlg = CaptureDialog(self)
        if tshark:
            dlg.tshark_path = tshark
            dlg._load_interfaces()

        if dlg.exec_() != CaptureDialog.Accepted:
            return

        iface  = dlg.selected_interface
        filt   = dlg.capture_filter
        maxpkt = dlg.max_packets

        if not iface:
            QMessageBox.warning(self, "Lỗi", "Chưa chọn interface.")
            return

        # Reset state
        self.packets = []
        self._live_buffer = []
        self._live_start_ts = time.time()
        self.packets_tab.clear_packets()
        self.act_suspicious.setEnabled(False)
        self.act_reanalyze.setEnabled(False)
        self.dashboard.start_live_mode()
        self.tabs.setCurrentIndex(0)

        self.act_open.setEnabled(False)
        self.act_live.setEnabled(False)
        self.act_stop.setEnabled(True)

        iface_short = iface.split("(")[0].strip()
        self.file_lbl.setText(f"Live: {iface_short}")
        self.live_badge.setText("● LIVE")
        self.live_badge.setVisible(True)
        self.status_lbl.setText(f"Đang capture  —  {iface}")

        self._capture_worker = TSharkCapture(
            tshark_path=dlg.tshark_path,
            interface=iface,
            bpf_filter=filt,
            max_packets=maxpkt,
        )
        self._capture_worker.packet_received.connect(self._on_live_packet)
        self._capture_worker.error_occurred.connect(self._on_live_error)
        self._capture_worker.status_changed.connect(self._on_live_status)
        self._capture_worker.finished.connect(self._on_capture_finished)
        self._capture_worker.start()

        self._live_timer.start()

    def stop_live_capture(self):
        self._live_timer.stop()
        if self._capture_worker:
            self._capture_worker.stop()
        # Final flush will happen in _on_capture_finished

    def _on_live_packet(self, pkt: PacketInfo):
        """Called from TSharkCapture thread via signal — safe to append to buffer."""
        self._live_buffer.append(pkt)

    def _on_live_error(self, msg: str):
        self._live_timer.stop()
        self._end_capture_ui()
        QMessageBox.critical(self, "Lỗi TShark", msg)

    def _on_live_status(self, msg: str):
        self.status_lbl.setText(f"TShark: {msg}")

    def _on_capture_finished(self):
        """TShark process exited — do final flush + analysis."""
        self._live_timer.stop()
        self._flush_live_buffer(final=True)
        self._end_capture_ui()

    def _flush_live_buffer(self, final: bool = False):
        """Drain _live_buffer → update UI, run detector on full packet list."""
        if not self._live_buffer:
            return

        batch = self._live_buffer[:]
        self._live_buffer.clear()

        # Extend master list
        self.packets.extend(batch)

        # Update packet table (streaming append)
        self.packets_tab.append_packets_batch(batch)

        # Re-run detector on ALL accumulated packets
        detector = DDoSDetector()
        alerts, stats = detector.analyze(self.packets)
        self.alerts = alerts
        self.stats  = stats

        # Update dashboard
        self.dashboard.update_data(self.packets, alerts, stats)

        # Update analysis only on final flush or every N packets to avoid lag
        if final or len(self.packets) % 500 < len(batch):
            self.analysis.update_alerts(alerts, stats)

        elapsed = time.time() - self._live_start_ts
        rate = len(self.packets) / max(elapsed, 0.001)
        self.status_lbl.setText(
            f"Live  |  {len(self.packets):,} pkts  |  {rate:.0f} pkt/s  "
            f"|  ⚠ {len(alerts)} cảnh báo"
        )

    def _end_capture_ui(self):
        self.act_open.setEnabled(True)
        self.act_live.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.act_reanalyze.setEnabled(bool(self.packets))
        self.act_suspicious.setEnabled(bool(self.packets))
        self.dashboard.stop_live_mode()
        self.live_badge.setVisible(False)
        self.file_lbl.setText(
            f"Live session — {len(self.packets):,} packets"
        )

    # ── Re-analyze ────────────────────────────────────────────────────────────

    def reanalyze(self):
        if not self.packets:
            return
        detector = DDoSDetector()
        alerts, stats = detector.analyze(self.packets)
        self.alerts = alerts
        self.stats  = stats
        self.dashboard.update_data(self.packets, alerts, stats)
        self.analysis.update_alerts(alerts, stats)
        self.status_lbl.setText(
            f"Phân tích lại hoàn tất  |  {len(alerts)} cảnh báo"
        )

    def _toggle_suspicious(self, checked: bool):
        if checked:
            self.packets_tab.suspicious_only.setCurrentIndex(1)
            self.tabs.setCurrentIndex(1)
        else:
            self.packets_tab.suspicious_only.setCurrentIndex(0)

    # ── Drag & Drop ───────────────────────────────────────────────────────────

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path.endswith((".pcap", ".pcapng")):
                self._load_file(path)
            else:
                QMessageBox.warning(self, "File không hỗ trợ",
                                    "Chỉ hỗ trợ file .pcap hoặc .pcapng")

    def setAcceptDrops(self, on: bool = True):
        super().setAcceptDrops(on)

    # ── About ────────────────────────────────────────────────────────────────

    def _show_about(self):
        QMessageBox.about(
            self, "Về Phần Mềm",
            "<h3>DDoS Analyzer v1.1</h3>"
            "<p>Phân tích và phát hiện tấn công DDoS<br>"
            "qua file PCAP hoặc live capture (TShark).</p>"
            "<p><b>Tính năng:</b><br>"
            "• Live capture qua TShark (real-time)<br>"
            "• Phát hiện SYN / UDP / ICMP / HTTP Flood<br>"
            "• Volumetric Attack, Single-source DoS, Port Scan<br>"
            "• Biểu đồ thời gian thực, lọc gói tin, giải pháp</p>"
            "<p><b>Công nghệ:</b> Python · PyQt5 · TShark · Scapy · Matplotlib</p>"
        )
