from typing import List

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QLineEdit, QPushButton, QComboBox,
    QAbstractItemView, QFrame, QSplitter, QTextEdit, QSizePolicy,
)
from PyQt5.QtCore import Qt, QSortFilterProxyModel
from PyQt5.QtGui import QColor, QFont, QBrush

from ...core.models import PacketInfo
from ..styles import DARK, PROTOCOL_COLORS

COLUMNS = ["No.", "Thời Gian", "Source IP", "Destination IP",
           "Protocol", "Kích Thước", "Flags", "Info"]
COL_NO, COL_TIME, COL_SRC, COL_DST, COL_PROTO, COL_LEN, COL_FLAGS, COL_INFO = range(8)


def _proto_color(proto: str) -> str:
    return PROTOCOL_COLORS.get(proto, DARK["muted"])


class PacketsTab(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_packets: List[PacketInfo] = []
        self._filtered: List[PacketInfo] = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Filter bar ──────────────────────────────────────────────────────
        bar = QFrame()
        bar.setStyleSheet(f"background-color: {DARK['bg2']};"
                          f"border-bottom: 1px solid {DARK['surface']};")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)
        bar_layout.setSpacing(8)

        bar_layout.addWidget(QLabel("Lọc:"))

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("IP, giao thức, port…  (ví dụ: 192.168.1.1  hoặc  TCP  hoặc  SYN)")
        self.filter_edit.setMinimumWidth(300)
        self.filter_edit.returnPressed.connect(self._apply_filter)

        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["Tất cả", "TCP", "UDP", "ICMP",
                                   "HTTP", "HTTPS", "DNS", "ARP", "OTHER"])
        self.proto_combo.setFixedWidth(100)
        self.proto_combo.currentTextChanged.connect(self._apply_filter)

        self.suspicious_only = QComboBox()
        self.suspicious_only.addItems(["Tất cả", "Nghi ngờ", "Bình thường"])
        self.suspicious_only.setFixedWidth(110)
        self.suspicious_only.currentTextChanged.connect(self._apply_filter)

        btn_filter  = QPushButton("Lọc")
        btn_filter.setFixedWidth(70)
        btn_filter.clicked.connect(self._apply_filter)

        btn_clear = QPushButton("Xóa")
        btn_clear.setObjectName("secondary")
        btn_clear.setFixedWidth(70)
        btn_clear.clicked.connect(self._clear_filter)

        self.count_lbl = QLabel("0 gói tin")
        self.count_lbl.setStyleSheet(f"color: {DARK['muted']}; font-size: 12px;")

        bar_layout.addWidget(self.filter_edit, 1)
        bar_layout.addWidget(self.proto_combo)
        bar_layout.addWidget(self.suspicious_only)
        bar_layout.addWidget(btn_filter)
        bar_layout.addWidget(btn_clear)
        bar_layout.addStretch()
        bar_layout.addWidget(self.count_lbl)

        root.addWidget(bar)

        # ── Splitter: table | detail ────────────────────────────────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(4)

        self.table = QTableWidget()
        self.table.setColumnCount(len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(COL_INFO, QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._on_row_selected)

        col_widths = [55, 100, 140, 140, 75, 75, 100]
        for i, w in enumerate(col_widths):
            self.table.setColumnWidth(i, w)

        # Detail panel
        detail_frame = QFrame()
        detail_frame.setStyleSheet(
            f"background-color: {DARK['bg2']};"
            f"border-top: 1px solid {DARK['surface']};"
        )
        dl = QVBoxLayout(detail_frame)
        dl.setContentsMargins(12, 8, 12, 8)
        dl.setSpacing(4)

        dlbl = QLabel("Chi Tiết Gói Tin")
        dlbl.setStyleSheet(f"color: {DARK['blue']}; font-weight: 700; font-size: 12px;")
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMaximumHeight(150)
        self.detail_text.setStyleSheet(
            f"background-color: {DARK['bg3']}; color: {DARK['text']};"
            f"border: none; font-family: 'Consolas', monospace; font-size: 12px;"
        )
        dl.addWidget(dlbl)
        dl.addWidget(self.detail_text)

        splitter.addWidget(self.table)
        splitter.addWidget(detail_frame)
        splitter.setSizes([700, 160])

        root.addWidget(splitter)

    # ── Public ────────────────────────────────────────────────────────────────

    def update_packets(self, packets: List[PacketInfo]):
        """Replace entire packet list (used after loading a PCAP file)."""
        self._all_packets = packets
        self._clear_filter()

    def clear_packets(self):
        """Reset state for a new live capture session."""
        self._all_packets = []
        self._filtered = []
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setSortingEnabled(True)
        self.count_lbl.setText("0 gói tin")

    def append_packets_batch(self, new_packets: List[PacketInfo]):
        """Append a batch of packets from live capture (fast path — no full rebuild)."""
        if not new_packets:
            return

        # Apply active filters to new packets only
        text = self.filter_edit.text().strip().lower()
        proto_sel = self.proto_combo.currentText()
        susp_sel = self.suspicious_only.currentText()

        visible = new_packets
        if text:
            visible = [p for p in visible if
                       text in p.src_ip.lower() or
                       text in p.dst_ip.lower() or
                       text in p.protocol.lower() or
                       text in p.info.lower() or
                       (p.src_port and text in str(p.src_port)) or
                       (p.dst_port and text in str(p.dst_port))]
        if proto_sel != "Tất cả":
            visible = [p for p in visible if p.protocol == proto_sel]
        if susp_sel == "Nghi ngờ":
            visible = [p for p in visible if p.is_suspicious]
        elif susp_sel == "Bình thường":
            visible = [p for p in visible if not p.is_suspicious]

        self._all_packets.extend(new_packets)
        self._filtered.extend(visible)

        # Append rows to table (no full rebuild)
        self.table.setSortingEnabled(False)
        start_row = self.table.rowCount()
        self.table.setRowCount(start_row + len(visible))

        for offset, p in enumerate(visible):
            row = start_row + offset
            self._fill_row(row, p)

        self.table.setSortingEnabled(True)
        self.count_lbl.setText(f"{len(self._all_packets):,} gói tin (live)")

        # Auto-scroll to bottom if user hasn't scrolled up
        vsb = self.table.verticalScrollBar()
        if vsb.value() >= vsb.maximum() - 40:
            self.table.scrollToBottom()

    def highlight_packets(self, packet_numbers: set):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_NO)
            if item and int(item.text()) in packet_numbers:
                for col in range(self.table.columnCount()):
                    cell = self.table.item(row, col)
                    if cell:
                        cell.setBackground(QColor(DARK["red"]).darker(200))

    # ── Private ───────────────────────────────────────────────────────────────

    def _apply_filter(self):
        text = self.filter_edit.text().strip().lower()
        proto_sel = self.proto_combo.currentText()
        susp_sel = self.suspicious_only.currentText()

        filtered = self._all_packets

        if text:
            filtered = [p for p in filtered if
                        text in p.src_ip.lower() or
                        text in p.dst_ip.lower() or
                        text in p.protocol.lower() or
                        text in p.info.lower() or
                        (p.src_port and text in str(p.src_port)) or
                        (p.dst_port and text in str(p.dst_port)) or
                        any(text == k.lower() for k, v in p.flags.items() if v)]

        if proto_sel != "Tất cả":
            filtered = [p for p in filtered if p.protocol == proto_sel]

        if susp_sel == "Nghi ngờ":
            filtered = [p for p in filtered if p.is_suspicious]
        elif susp_sel == "Bình thường":
            filtered = [p for p in filtered if not p.is_suspicious]

        self._filtered = filtered
        self._populate_table(filtered)

    def _clear_filter(self):
        self.filter_edit.clear()
        self.proto_combo.setCurrentIndex(0)
        self.suspicious_only.setCurrentIndex(0)
        self._filtered = self._all_packets
        self._populate_table(self._all_packets)

    def _populate_table(self, packets: List[PacketInfo]):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setRowCount(len(packets))
        for row, p in enumerate(packets):
            self._fill_row(row, p)
        self.table.setSortingEnabled(True)
        self.count_lbl.setText(f"{len(packets):,} gói tin")

    def _fill_row(self, row: int, p: PacketInfo):
        cells = [
            str(p.number),
            p.time_str,
            p.src_ip,
            p.dst_ip,
            p.protocol,
            str(p.length),
            p.flags_str,
            p.info,
        ]
        proto_color = _proto_color(p.protocol)
        for col, text in enumerate(cells):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if col == COL_PROTO:
                item.setForeground(QColor(proto_color))
                item.setFont(QFont("Consolas", 11, QFont.Bold))
            if p.is_suspicious:
                item.setBackground(QColor(DARK["red"]).darker(250))
            self.table.setItem(row, col, item)

    def _on_row_selected(self):
        rows = self.table.selectedItems()
        if not rows:
            return
        row = self.table.currentRow()
        no_item = self.table.item(row, COL_NO)
        if not no_item:
            return
        pkt_no = int(no_item.text())
        pkt = next((p for p in self._all_packets if p.number == pkt_no), None)
        if pkt:
            self._show_detail(pkt)

    def _show_detail(self, p: PacketInfo):
        flags_str = ", ".join(f"{k}={v}" for k, v in p.flags.items()) or "N/A"
        text = (
            f"Số thứ tự  : {p.number}\n"
            f"Thời gian  : {p.time_str} s\n"
            f"Source     : {p.src_ip}" +
            (f":{p.src_port}" if p.src_port else "") + "\n"
            f"Destination: {p.dst_ip}" +
            (f":{p.dst_port}" if p.dst_port else "") + "\n"
            f"Giao thức  : {p.protocol}\n"
            f"Kích thước : {p.length} bytes\n"
            f"Flags      : {flags_str}\n"
            f"Nghi ngờ   : {'CÓ ⚠' if p.is_suspicious else 'Không'}\n"
            f"Info       : {p.info}"
        )
        self.detail_text.setPlainText(text)
