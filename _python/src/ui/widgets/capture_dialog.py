"""
Dialog chọn interface và cấu hình live capture.
"""
from typing import Optional

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QLineEdit, QSpinBox, QPushButton, QFrame, QGroupBox,
    QFormLayout, QTextEdit, QSizePolicy, QMessageBox,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from ...core.tshark_capture import find_tshark, get_interfaces
from ..styles import DARK


class CaptureDialog(QDialog):
    """Modal dialog to configure a live TShark capture session."""

    # Common BPF capture filters
    _FILTER_PRESETS = {
        "Tất cả":                    "",
        "Chỉ TCP":                   "tcp",
        "Chỉ UDP":                   "udp",
        "Chỉ ICMP":                  "icmp",
        "HTTP/HTTPS (port 80/443)":  "tcp port 80 or tcp port 443",
        "DNS (port 53)":             "udp port 53",
        "Loại trừ broadcast":        "not broadcast and not multicast",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Cấu Hình Live Capture")
        self.setMinimumWidth(540)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog  {{ background-color: {DARK['bg2']}; color: {DARK['text']}; }}
            QLabel   {{ background: transparent; }}
            QGroupBox {{
                border: 1px solid {DARK['surface']};
                border-radius: 6px;
                margin-top: 10px;
                padding: 8px;
                font-weight: 600;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px;
                color: {DARK['blue']};
            }}
        """)

        self.tshark_path: Optional[str] = find_tshark()
        self._interfaces = []
        self._build_ui()
        self._load_interfaces()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # TShark status banner
        self._tshark_banner = QLabel()
        self._tshark_banner.setWordWrap(True)
        self._tshark_banner.setAlignment(Qt.AlignCenter)
        root.addWidget(self._tshark_banner)

        # ── Interface group ──────────────────────────────────────────────────
        iface_group = QGroupBox("Giao Diện Mạng (Network Interface)")
        iface_form = QFormLayout(iface_group)
        iface_form.setSpacing(8)

        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(380)
        iface_form.addRow("Interface:", self.iface_combo)

        refresh_btn = QPushButton("Làm mới")
        refresh_btn.setObjectName("secondary")
        refresh_btn.setFixedWidth(90)
        refresh_btn.clicked.connect(self._load_interfaces)

        row = QHBoxLayout()
        row.addWidget(self.iface_combo, 1)
        row.addWidget(refresh_btn)
        iface_form.addRow("", row)
        root.addWidget(iface_group)

        # ── Filter group ─────────────────────────────────────────────────────
        filter_group = QGroupBox("Bộ Lọc (Capture Filter — BPF)")
        fl = QVBoxLayout(filter_group)
        fl.setSpacing(6)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Preset:"))
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(list(self._FILTER_PRESETS.keys()))
        self.preset_combo.currentTextChanged.connect(self._on_preset_changed)
        preset_row.addWidget(self.preset_combo, 1)
        fl.addLayout(preset_row)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            "BPF filter — vd: tcp port 80  |  not host 10.0.0.1  |  src net 192.168.1.0/24"
        )
        fl.addWidget(self.filter_edit)
        root.addWidget(filter_group)

        # ── Options group ────────────────────────────────────────────────────
        opt_group = QGroupBox("Tùy Chọn")
        opt_form = QFormLayout(opt_group)
        opt_form.setSpacing(8)

        self.max_spin = QSpinBox()
        self.max_spin.setRange(0, 100_000)
        self.max_spin.setValue(0)
        self.max_spin.setSpecialValueText("Không giới hạn")
        self.max_spin.setSuffix("  packets")
        opt_form.addRow("Tối đa:", self.max_spin)

        root.addWidget(opt_group)

        # ── Note ────────────────────────────────────────────────────────────
        note = QLabel(
            "Lưu ý: Capture live yêu cầu quyền Administrator (Windows)\n"
            "hoặc sudo / group wireshark (Linux)."
        )
        note.setStyleSheet(f"color: {DARK['yellow']}; font-size: 11px;")
        note.setWordWrap(True)
        root.addWidget(note)

        # ── Buttons ──────────────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {DARK['surface']};")
        root.addWidget(sep)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self.start_btn = QPushButton("  Bắt Đầu Capture")
        self.start_btn.setMinimumWidth(160)
        self.start_btn.clicked.connect(self.accept)

        cancel_btn = QPushButton("Hủy")
        cancel_btn.setObjectName("secondary")
        cancel_btn.setFixedWidth(80)
        cancel_btn.clicked.connect(self.reject)

        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self.start_btn)
        root.addLayout(btn_row)

    # ── Load interfaces ───────────────────────────────────────────────────────

    def _load_interfaces(self):
        self.iface_combo.clear()

        if not self.tshark_path:
            self._set_tshark_status(found=False)
            self.start_btn.setEnabled(False)
            return

        self._set_tshark_status(found=True)
        self._interfaces = get_interfaces(self.tshark_path)

        if not self._interfaces:
            self.iface_combo.addItem("(Không tìm thấy interface — kiểm tra quyền Admin)")
            self.start_btn.setEnabled(False)
        else:
            for iface in self._interfaces:
                self.iface_combo.addItem(iface["label"])
            self.start_btn.setEnabled(True)

    def _set_tshark_status(self, found: bool):
        if found:
            self._tshark_banner.setText(
                f"TShark:  {self.tshark_path}"
            )
            self._tshark_banner.setStyleSheet(
                f"background-color: {DARK['bg3']}; color: {DARK['green']};"
                f"border-radius: 4px; padding: 5px 10px; font-size: 11px;"
            )
        else:
            self._tshark_banner.setText(
                "Không tìm thấy TShark.\n"
                "Cài Wireshark (https://www.wireshark.org) rồi thử lại."
            )
            self._tshark_banner.setStyleSheet(
                f"background-color: {DARK['bg3']}; color: {DARK['red']};"
                f"border-radius: 4px; padding: 8px; font-size: 12px;"
            )

    def _on_preset_changed(self, text: str):
        val = self._FILTER_PRESETS.get(text, "")
        self.filter_edit.setText(val)

    # ── Result accessors ──────────────────────────────────────────────────────

    @property
    def selected_interface(self) -> str:
        idx = self.iface_combo.currentIndex()
        if 0 <= idx < len(self._interfaces):
            return self._interfaces[idx]["name"]
        return self.iface_combo.currentText().split(".")[0].strip()

    @property
    def capture_filter(self) -> str:
        return self.filter_edit.text().strip()

    @property
    def max_packets(self) -> int:
        return self.max_spin.value()
