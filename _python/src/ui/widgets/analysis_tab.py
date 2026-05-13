from typing import List, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QTextEdit, QSplitter, QSizePolicy,
    QGridLayout, QPushButton,
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont

import matplotlib
matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from ...core.models import Alert, AlertSeverity, NetworkStats, AttackType
from ..styles import DARK, MPL_STYLE


SEV_ICON = {
    AlertSeverity.LOW:      "🟡",
    AlertSeverity.MEDIUM:   "🟠",
    AlertSeverity.HIGH:     "🔴",
    AlertSeverity.CRITICAL: "💀",
}

ATTACK_EXPLAIN = {
    AttackType.SYN_FLOOD: (
        "SYN Flood là kiểu tấn công khai thác quá trình bắt tay 3 bước của TCP.\n"
        "Kẻ tấn công gửi hàng loạt gói SYN (yêu cầu kết nối) nhưng không hoàn tất\n"
        "ACK, khiến server giữ hàng nghìn kết nối 'half-open', cạn kiệt tài nguyên."
    ),
    AttackType.UDP_FLOOD: (
        "UDP Flood gửi lượng lớn gói UDP ngẫu nhiên đến nhiều port.\n"
        "Server phải xử lý từng gói và trả về ICMP 'Unreachable' nếu không có service,\n"
        "dẫn đến quá tải CPU và băng thông."
    ),
    AttackType.ICMP_FLOOD: (
        "ICMP Flood (Ping Flood) gửi ồ ạt ICMP Echo Request.\n"
        "Smurf Attack là biến thể dùng broadcast để khuếch đại lưu lượng."
    ),
    AttackType.HTTP_FLOOD: (
        "HTTP Flood gửi hàng loạt HTTP GET/POST hợp lệ.\n"
        "Khó phân biệt với traffic thường, nhắm vào lớp ứng dụng (Layer 7)."
    ),
    AttackType.VOLUMETRIC: (
        "Tấn công Volumetric bão hòa băng thông đường truyền.\n"
        "Có thể kết hợp nhiều vector: UDP, ICMP, DNS amplification…"
    ),
    AttackType.SINGLE_SOURCE: (
        "DoS đơn nguồn: một IP duy nhất chiếm phần lớn lưu lượng.\n"
        "Dễ chặn hơn DDoS phân tán nhưng vẫn có thể làm quá tải dịch vụ."
    ),
    AttackType.PORT_SCAN: (
        "Port Scan là hoạt động trinh sát, quét nhiều port để tìm dịch vụ đang mở.\n"
        "Thường là bước chuẩn bị trước khi thực hiện tấn công thật sự."
    ),
}


class AlertCard(QFrame):
    clicked = pyqtSignal(object)

    def __init__(self, alert: Alert, parent=None):
        super().__init__(parent)
        self.alert = alert
        self.setFrameShape(QFrame.StyledPanel)
        self.setCursor(Qt.PointingHandCursor)
        self._selected = False
        self._update_style(False)
        self._build()

    def _update_style(self, selected: bool):
        border = self.alert.severity_color
        bg = self.alert.severity_bg if not selected else DARK["overlay"]
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg};
                border-left: 4px solid {border};
                border-radius: 6px;
            }}
            QFrame:hover {{
                background-color: {DARK['overlay']};
            }}
        """)

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(3)

        # Header row
        h = QHBoxLayout()
        h.setSpacing(8)

        icon = SEV_ICON.get(self.alert.severity, "")
        sev_lbl = QLabel(f"{icon} {self.alert.severity.value}")
        sev_lbl.setStyleSheet(
            f"color: {self.alert.severity_color}; font-weight: 700; font-size: 12px;"
        )

        type_lbl = QLabel(self.alert.attack_type.value)
        type_lbl.setStyleSheet(f"color: {DARK['text']}; font-weight: 600; font-size: 13px;")

        rate_lbl = QLabel(f"{self.alert.rate:.0f} pkt/s")
        rate_lbl.setStyleSheet(f"color: {DARK['muted']}; font-size: 11px;")
        rate_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        h.addWidget(sev_lbl)
        h.addWidget(type_lbl, 1)
        h.addWidget(rate_lbl)
        layout.addLayout(h)

        src_text = ", ".join(self.alert.source_ips[:3])
        if len(self.alert.source_ips) > 3:
            src_text += f" (+{len(self.alert.source_ips)-3} more)"
        src_lbl = QLabel(f"Nguồn: {src_text}")
        src_lbl.setStyleSheet(f"color: {DARK['subtext']}; font-size: 11px;")
        src_lbl.setWordWrap(True)
        layout.addWidget(src_lbl)

        if self.alert.target_ip:
            tgt_lbl = QLabel(f"Đích: {self.alert.target_ip}")
            tgt_lbl.setStyleSheet(f"color: {DARK['subtext']}; font-size: 11px;")
            layout.addWidget(tgt_lbl)

        meta_lbl = QLabel(
            f"{self.alert.packet_count:,} packets  •  "
            f"T={self.alert.start_time:.3f}s – {self.alert.end_time:.3f}s"
        )
        meta_lbl.setStyleSheet(f"color: {DARK['muted']}; font-size: 10px;")
        layout.addWidget(meta_lbl)

    def mousePressEvent(self, event):
        self.clicked.emit(self.alert)
        super().mousePressEvent(event)

    def set_selected(self, sel: bool):
        self._selected = sel
        self._update_style(sel)


class SeverityBarChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.fig = Figure(figsize=(4, 2.0), tight_layout=True)
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setStyleSheet(f"background-color: {DARK['bg2']};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

    def update(self, alerts: List[Alert]):
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor(DARK["bg2"])
        self.fig.patch.set_facecolor(DARK["bg2"])
        for k, v in MPL_STYLE.items():
            try:
                import matplotlib.pyplot as plt
                plt.rcParams[k] = v
            except Exception:
                pass

        counts = {s: 0 for s in AlertSeverity}
        for a in alerts:
            counts[a.severity] += 1

        labels = [s.value for s in AlertSeverity]
        values = [counts[s] for s in AlertSeverity]
        colors_list = [
            DARK["yellow"], DARK["peach"], DARK["red"], "#D20F39"
        ]
        bars = ax.bar(labels, values, color=colors_list, edgecolor="none", width=0.55)
        for bar, val in zip(bars, values):
            if val:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                        str(val), ha="center", va="bottom",
                        color=DARK["text"], fontsize=10, fontweight="bold")

        ax.set_title("Phân Bố Mức Độ Cảnh Báo", color=DARK["text"],
                     fontsize=11, fontweight="bold", pad=6)
        ax.set_ylabel("Số cảnh báo", color=DARK["muted"], fontsize=9)
        ax.tick_params(colors=DARK["muted"], labelsize=9)
        for spine in ax.spines.values():
            spine.set_edgecolor(DARK["surface"])
        ax.set_ylim(0, max(values + [1]) * 1.3)
        self.canvas.draw()


class AnalysisTab(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts: List[Alert] = []
        self._cards: List[AlertCard] = []
        self._selected_card: Optional[AlertCard] = None
        self._build_ui()

    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(3)

        # ── Left: alert list ────────────────────────────────────────────────
        left = QWidget()
        left.setMinimumWidth(340)
        left.setMaximumWidth(460)
        left.setStyleSheet(f"background-color: {DARK['bg2']};")
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(0)

        left_header = QFrame()
        left_header.setStyleSheet(
            f"background-color: {DARK['bg2']};"
            f"border-bottom: 1px solid {DARK['surface']};"
        )
        lh = QHBoxLayout(left_header)
        lh.setContentsMargins(12, 10, 12, 10)
        title_lbl = QLabel("Danh Sách Cảnh Báo")
        title_lbl.setStyleSheet(f"color: {DARK['text']}; font-weight: 700; font-size: 14px;")
        self.alert_count_lbl = QLabel("0 cảnh báo")
        self.alert_count_lbl.setStyleSheet(f"color: {DARK['muted']}; font-size: 12px;")
        lh.addWidget(title_lbl, 1)
        lh.addWidget(self.alert_count_lbl)
        lv.addWidget(left_header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(f"background-color: {DARK['bg2']}; border: none;")

        self._list_container = QWidget()
        self._list_container.setStyleSheet(f"background-color: {DARK['bg2']};")
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setContentsMargins(8, 8, 8, 8)
        self._list_layout.setSpacing(6)
        self._list_layout.addStretch()

        scroll.setWidget(self._list_container)
        lv.addWidget(scroll, 1)

        # ── Right: detail panel ─────────────────────────────────────────────
        right = QWidget()
        right.setStyleSheet(f"background-color: {DARK['bg']};")
        rv = QVBoxLayout(right)
        rv.setContentsMargins(16, 16, 16, 16)
        rv.setSpacing(12)

        self.detail_title = QLabel("Chọn một cảnh báo để xem chi tiết")
        self.detail_title.setStyleSheet(
            f"color: {DARK['text']}; font-size: 16px; font-weight: 700;"
        )
        rv.addWidget(self.detail_title)

        # Severity bar chart
        self.sev_chart = SeverityBarChart()
        self.sev_chart.setMinimumHeight(160)
        rv.addWidget(self.sev_chart)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {DARK['surface']};")
        rv.addWidget(sep)

        # Description
        desc_lbl = QLabel("Mô tả chi tiết")
        desc_lbl.setStyleSheet(
            f"color: {DARK['blue']}; font-weight: 700; font-size: 13px;"
        )
        rv.addWidget(desc_lbl)

        self.desc_text = QTextEdit()
        self.desc_text.setReadOnly(True)
        self.desc_text.setMaximumHeight(100)
        self.desc_text.setStyleSheet(
            f"background-color: {DARK['bg2']}; color: {DARK['text']};"
            f"border: 1px solid {DARK['surface']}; border-radius: 6px;"
            f"padding: 8px; font-size: 12px; font-family: 'Segoe UI';"
        )
        rv.addWidget(self.desc_text)

        # Attack mechanism
        mech_lbl = QLabel("Cơ chế tấn công")
        mech_lbl.setStyleSheet(
            f"color: {DARK['blue']}; font-weight: 700; font-size: 13px;"
        )
        rv.addWidget(mech_lbl)

        self.mech_text = QTextEdit()
        self.mech_text.setReadOnly(True)
        self.mech_text.setMaximumHeight(90)
        self.mech_text.setStyleSheet(
            f"background-color: {DARK['bg2']}; color: {DARK['subtext']};"
            f"border: 1px solid {DARK['surface']}; border-radius: 6px;"
            f"padding: 8px; font-size: 12px;"
        )
        rv.addWidget(self.mech_text)

        # Recommendation
        rec_lbl = QLabel("Giải pháp phòng chống")
        rec_lbl.setStyleSheet(
            f"color: {DARK['green']}; font-weight: 700; font-size: 13px;"
        )
        rv.addWidget(rec_lbl)

        self.rec_text = QTextEdit()
        self.rec_text.setReadOnly(True)
        self.rec_text.setStyleSheet(
            f"background-color: {DARK['bg3']}; color: {DARK['green']};"
            f"border: 1px solid {DARK['surface']}; border-radius: 6px;"
            f"padding: 8px; font-size: 12px; font-family: 'Consolas';"
        )
        rv.addWidget(self.rec_text, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([380, 800])
        root.addWidget(splitter)

    # ── Public ────────────────────────────────────────────────────────────────

    def update_alerts(self, alerts: List[Alert], stats: Optional[NetworkStats] = None):
        self._alerts = alerts

        # Clear list
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._cards.clear()
        self._selected_card = None

        self.alert_count_lbl.setText(f"{len(alerts)} cảnh báo")

        if not alerts:
            no_alert = QLabel("Không phát hiện tấn công DDoS.\nTraffic bình thường.")
            no_alert.setStyleSheet(
                f"color: {DARK['green']}; font-size: 13px; padding: 20px; text-align: center;"
            )
            no_alert.setAlignment(Qt.AlignCenter)
            self._list_layout.insertWidget(0, no_alert)
            self.detail_title.setText("Không phát hiện tấn công")
            self.desc_text.setPlainText("Lưu lượng mạng trong ngưỡng bình thường.")
            self.mech_text.clear()
            self.rec_text.clear()
        else:
            for alert in alerts:
                card = AlertCard(alert)
                card.clicked.connect(self._on_alert_selected)
                self._cards.append(card)
                self._list_layout.insertWidget(self._list_layout.count() - 1, card)

            # Auto-select first
            if self._cards:
                self._on_alert_selected(self._cards[0].alert)
                self._cards[0].set_selected(True)
                self._selected_card = self._cards[0]

        self.sev_chart.update(alerts)

    # ── Private ───────────────────────────────────────────────────────────────

    def _on_alert_selected(self, alert: Alert):
        # Deselect previous
        if self._selected_card:
            self._selected_card.set_selected(False)

        # Find and select new card
        for card in self._cards:
            if card.alert.id == alert.id:
                card.set_selected(True)
                self._selected_card = card
                break

        self.detail_title.setText(f"{SEV_ICON.get(alert.severity,'')}  {alert.attack_type.value}")

        self.desc_text.setPlainText(alert.description)

        explain = ATTACK_EXPLAIN.get(alert.attack_type, "Không có thông tin.")
        self.mech_text.setPlainText(explain)

        self.rec_text.setPlainText(
            alert.recommendation if alert.recommendation
            else "Xem tài liệu bảo mật để biết thêm giải pháp."
        )
