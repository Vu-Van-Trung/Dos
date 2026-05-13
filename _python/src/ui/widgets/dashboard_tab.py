from typing import List, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QGridLayout, QScrollArea, QSizePolicy,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor

import matplotlib
matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import numpy as np

from ...core.models import PacketInfo, Alert, NetworkStats, AlertSeverity
from ..styles import DARK, MPL_STYLE, PROTOCOL_COLORS


def _apply_mpl_style(ax):
    for k, v in MPL_STYLE.items():
        try:
            plt.rcParams[k] = v
        except Exception:
            pass
    ax.set_facecolor(DARK["bg2"])
    ax.tick_params(colors=DARK["muted"], labelsize=9)
    for spine in ax.spines.values():
        spine.set_edgecolor(DARK["surface"])


class MetricCard(QFrame):
    def __init__(self, title: str, value: str = "—", color: str = None, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumHeight(80)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {DARK['bg2']};
                border: 1px solid {DARK['surface']};
                border-radius: 8px;
                padding: 4px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        self._title_lbl = QLabel(title)
        self._title_lbl.setStyleSheet(f"color: {DARK['muted']}; font-size: 11px; font-weight:600;")

        accent = color or DARK["blue"]
        self._value_lbl = QLabel(value)
        self._value_lbl.setStyleSheet(
            f"color: {accent}; font-size: 24px; font-weight: 700;"
        )
        self._value_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        layout.addWidget(self._title_lbl)
        layout.addWidget(self._value_lbl)

    def set_value(self, value: str, color: str = None):
        self._value_lbl.setText(value)
        if color:
            self._value_lbl.setStyleSheet(
                f"color: {color}; font-size: 24px; font-weight: 700;"
            )


class TrafficChart(QWidget):
    """Packets/second over time — line chart."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.fig = Figure(figsize=(8, 2.4), tight_layout=True)
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setStyleSheet(f"background-color: {DARK['bg2']};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

    def update(self, stats: Optional[NetworkStats]):
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        _apply_mpl_style(ax)

        if stats and stats.time_buckets:
            xs = [t - stats.start_time for t in stats.time_buckets]
            ys = stats.packets_per_second
            ax.fill_between(xs, ys, alpha=0.25, color=DARK["blue"])
            ax.plot(xs, ys, color=DARK["blue"], linewidth=1.5, label="Packets/s")

            # Mark peak
            if ys:
                peak_idx = int(np.argmax(ys))
                ax.axvline(xs[peak_idx], color=DARK["red"], linestyle="--",
                           linewidth=1, alpha=0.6, label=f"Peak: {ys[peak_idx]} pkt/s")
        else:
            ax.text(0.5, 0.5, "Chưa có dữ liệu",
                    ha="center", va="center", color=DARK["muted"], fontsize=12,
                    transform=ax.transAxes)

        ax.set_title("Lưu Lượng Mạng Theo Thời Gian", color=DARK["text"],
                     fontsize=12, pad=8, fontweight="bold")
        ax.set_xlabel("Thời gian (giây)", color=DARK["muted"], fontsize=9)
        ax.set_ylabel("Packets/s", color=DARK["muted"], fontsize=9)
        ax.legend(fontsize=9, framealpha=0.3)
        self.fig.patch.set_facecolor(DARK["bg2"])
        self.canvas.draw()


class ProtocolPieChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.fig = Figure(figsize=(4, 2.8), tight_layout=True)
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setStyleSheet(f"background-color: {DARK['bg2']};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

    def update(self, stats: Optional[NetworkStats]):
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor(DARK["bg2"])
        self.fig.patch.set_facecolor(DARK["bg2"])

        if stats and stats.protocol_counts:
            labels = list(stats.protocol_counts.keys())
            sizes = list(stats.protocol_counts.values())
            colors = [PROTOCOL_COLORS.get(l, DARK["muted"]) for l in labels]

            wedges, texts, autotexts = ax.pie(
                sizes, labels=None, colors=colors,
                autopct="%1.1f%%", startangle=90,
                pctdistance=0.75,
                wedgeprops=dict(width=0.55, edgecolor=DARK["bg2"], linewidth=2),
            )
            for at in autotexts:
                at.set_color(DARK["bg2"])
                at.set_fontsize(8)
                at.set_fontweight("bold")

            ax.legend(wedges, labels, loc="center left",
                      bbox_to_anchor=(1, 0.5), fontsize=9,
                      framealpha=0.2, labelcolor=DARK["text"])
        else:
            ax.text(0.5, 0.5, "Chưa có dữ liệu",
                    ha="center", va="center", color=DARK["muted"], fontsize=11,
                    transform=ax.transAxes)

        ax.set_title("Phân Bố Giao Thức", color=DARK["text"],
                     fontsize=11, fontweight="bold", pad=6)
        self.canvas.draw()


class TopIPChart(QWidget):
    def __init__(self, title: str = "Top Source IPs", parent=None):
        super().__init__(parent)
        self.title = title
        self.fig = Figure(figsize=(4, 2.8), tight_layout=True)
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setStyleSheet(f"background-color: {DARK['bg2']};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

    def update(self, ip_counts: dict, top_n: int = 8):
        self.fig.clear()
        ax = self.fig.add_subplot(111)
        _apply_mpl_style(ax)
        self.fig.patch.set_facecolor(DARK["bg2"])

        if ip_counts:
            sorted_items = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
            ips = [item[0] for item in reversed(sorted_items)]
            counts = [item[1] for item in reversed(sorted_items)]
            bar_colors = [DARK["red"] if i == len(ips) - 1 else DARK["blue"]
                          for i in range(len(ips))]
            bars = ax.barh(ips, counts, color=bar_colors, height=0.6,
                           edgecolor="none")
            for bar, count in zip(bars, counts):
                ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                        str(count), va="center", ha="left",
                        color=DARK["muted"], fontsize=8)
        else:
            ax.text(0.5, 0.5, "Chưa có dữ liệu",
                    ha="center", va="center", color=DARK["muted"], fontsize=11,
                    transform=ax.transAxes)

        ax.set_title(self.title, color=DARK["text"], fontsize=11,
                     fontweight="bold", pad=6)
        ax.set_xlabel("Số packets", color=DARK["muted"], fontsize=9)
        self.canvas.draw()


class AlertSummaryWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {DARK['bg2']};
                border: 1px solid {DARK['surface']};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        title = QLabel("Tóm Tắt Cảnh Báo")
        title.setStyleSheet(
            f"color: {DARK['text']}; font-size: 12px; font-weight: 700;"
        )
        layout.addWidget(title)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setStyleSheet("background: transparent;")
        self._container = QWidget()
        self._container.setStyleSheet("background: transparent;")
        self._vbox = QVBoxLayout(self._container)
        self._vbox.setContentsMargins(0, 0, 0, 0)
        self._vbox.setSpacing(4)
        self._vbox.addStretch()
        self._scroll.setWidget(self._container)
        layout.addWidget(self._scroll)

    def update(self, alerts: List[Alert]):
        # Clear existing items
        while self._vbox.count() > 1:
            item = self._vbox.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not alerts:
            lbl = QLabel("Không phát hiện tấn công.")
            lbl.setStyleSheet(f"color: {DARK['green']}; font-size: 12px; padding: 4px;")
            self._vbox.insertWidget(0, lbl)
            return

        for alert in alerts[:10]:
            row = QFrame()
            row.setStyleSheet(f"""
                QFrame {{
                    background-color: {alert.severity_bg};
                    border-left: 3px solid {alert.severity_color};
                    border-radius: 4px;
                    padding: 2px 4px;
                }}
            """)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(8, 4, 8, 4)

            sev_badge = QLabel(f"[{alert.severity.value}]")
            sev_badge.setStyleSheet(
                f"color: {alert.severity_color}; font-weight: 700; font-size: 11px;"
            )
            sev_badge.setFixedWidth(70)

            info = QLabel(f"{alert.attack_type.value} — {alert.packet_count} pkts @ {alert.rate:.0f}/s")
            info.setStyleSheet(f"color: {DARK['text']}; font-size: 11px;")

            rl.addWidget(sev_badge)
            rl.addWidget(info, 1)
            self._vbox.insertWidget(self._vbox.count() - 1, row)


class DashboardTab(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._live_mode = False
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ── Metric cards row ────────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        self.card_pkts    = MetricCard("Tổng Gói Tin",    "—", DARK["blue"])
        self.card_alerts  = MetricCard("Cảnh Báo",        "—", DARK["red"])
        self.card_bw      = MetricCard("Băng Thông TB",   "—", DARK["teal"])
        self.card_maxpps  = MetricCard("Đỉnh Lưu Lượng",  "—", DARK["yellow"])
        self.card_sources = MetricCard("Nguồn IP",        "—", DARK["mauve"])
        self.card_dur     = MetricCard("Thời Gian Capture","—", DARK["subtext"])

        for c in (self.card_pkts, self.card_alerts, self.card_bw,
                  self.card_maxpps, self.card_sources, self.card_dur):
            c.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            cards_row.addWidget(c)
        root.addLayout(cards_row)

        # ── Traffic chart (full width) ──────────────────────────────────────
        self.traffic_chart = TrafficChart()
        self.traffic_chart.setMinimumHeight(180)
        root.addWidget(self.traffic_chart)

        # ── Bottom row: pie + bar + alerts ──────────────────────────────────
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(12)

        self.pie_chart  = ProtocolPieChart()
        self.pie_chart.setMinimumHeight(220)

        self.ip_chart   = TopIPChart("Top Source IPs")
        self.ip_chart.setMinimumHeight(220)

        self.alert_summary = AlertSummaryWidget()
        self.alert_summary.setMinimumHeight(220)
        self.alert_summary.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        bottom_row.addWidget(self.pie_chart, 3)
        bottom_row.addWidget(self.ip_chart, 3)
        bottom_row.addWidget(self.alert_summary, 4)
        root.addLayout(bottom_row)

    def update_data(self, packets: List[PacketInfo],
                    alerts: List[Alert],
                    stats: Optional[NetworkStats]):
        if not stats:
            return

        sev_color = DARK["green"]
        if alerts:
            sev_color = alerts[0].severity_color

        self.card_pkts.set_value(f"{stats.total_packets:,}")
        self.card_alerts.set_value(str(len(alerts)), sev_color if alerts else DARK["green"])
        self.card_bw.set_value(f"{stats.avg_bandwidth_mbps:.2f} MB/s")
        self.card_maxpps.set_value(f"{stats.max_pps:,.0f} pkt/s")
        self.card_sources.set_value(str(len(stats.src_ip_counts)))

        dur_text = f"{stats.duration:.1f} s"
        if self._live_mode:
            dur_text += "  ●"   # live indicator
        self.card_dur.set_value(dur_text)

        self.traffic_chart.update(stats)
        self.pie_chart.update(stats)
        self.ip_chart.update(stats.src_ip_counts)
        self.alert_summary.update(alerts)

    def start_live_mode(self):
        """Switch metric cards to live display (update faster)."""
        self._live_mode = True
        self.card_dur._title_lbl.setText("Thời Gian  ●LIVE")
        self.card_dur._title_lbl.setStyleSheet(
            f"color: {DARK['red']}; font-size: 11px; font-weight:600;"
        )

    def stop_live_mode(self):
        self._live_mode = False
        self.card_dur._title_lbl.setText("Thời Gian Capture")
        self.card_dur._title_lbl.setStyleSheet(
            f"color: {DARK['muted']}; font-size: 11px; font-weight:600;"
        )
