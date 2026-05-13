DARK = {
    "bg":       "#1E1E2E",
    "bg2":      "#181825",
    "bg3":      "#11111B",
    "surface":  "#313244",
    "overlay":  "#45475A",
    "text":     "#CDD6F4",
    "subtext":  "#BAC2DE",
    "muted":    "#6C7086",
    "blue":     "#89B4FA",
    "lavender": "#B4BEFE",
    "green":    "#A6E3A1",
    "yellow":   "#F9E64F",
    "peach":    "#FAB387",
    "red":      "#F38BA8",
    "maroon":   "#EBA0AC",
    "teal":     "#94E2D5",
    "sky":      "#89DCEB",
    "mauve":    "#CBA6F7",
}

APP_STYLESHEET = f"""
QMainWindow, QDialog {{
    background-color: {DARK['bg']};
}}

QWidget {{
    background-color: {DARK['bg']};
    color: {DARK['text']};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 13px;
}}

/* ── Tabs ──────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {DARK['surface']};
    background-color: {DARK['bg']};
}}
QTabBar::tab {{
    background-color: {DARK['bg2']};
    color: {DARK['muted']};
    padding: 9px 24px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 500;
    min-width: 110px;
}}
QTabBar::tab:selected {{
    background-color: {DARK['bg']};
    color: {DARK['text']};
    border-bottom: 2px solid {DARK['blue']};
}}
QTabBar::tab:hover:!selected {{
    color: {DARK['subtext']};
    background-color: {DARK['bg']};
}}

/* ── Toolbar ───────────────────────────── */
QToolBar {{
    background-color: {DARK['bg2']};
    border-bottom: 1px solid {DARK['surface']};
    spacing: 6px;
    padding: 5px 8px;
}}
QToolBar QToolButton {{
    background-color: transparent;
    color: {DARK['subtext']};
    border: none;
    padding: 5px 12px;
    border-radius: 4px;
    font-size: 13px;
}}
QToolBar QToolButton:hover {{
    background-color: {DARK['surface']};
    color: {DARK['text']};
}}
QToolBar QToolButton:pressed {{
    background-color: {DARK['overlay']};
}}
QToolBar QToolButton:disabled {{
    color: {DARK['muted']};
}}

/* ── Buttons ───────────────────────────── */
QPushButton {{
    background-color: {DARK['blue']};
    color: {DARK['bg']};
    border: none;
    padding: 6px 18px;
    border-radius: 5px;
    font-weight: 600;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: {DARK['lavender']};
}}
QPushButton:pressed {{
    background-color: {DARK['subtext']};
}}
QPushButton:disabled {{
    background-color: {DARK['overlay']};
    color: {DARK['muted']};
}}
QPushButton#danger {{
    background-color: {DARK['red']};
    color: {DARK['bg']};
}}
QPushButton#secondary {{
    background-color: {DARK['surface']};
    color: {DARK['text']};
}}

/* ── Table ─────────────────────────────── */
QTableWidget {{
    background-color: {DARK['bg2']};
    alternate-background-color: {DARK['bg']};
    gridline-color: {DARK['surface']};
    selection-background-color: {DARK['overlay']};
    selection-color: {DARK['text']};
    border: none;
    border-radius: 0px;
}}
QTableWidget::item {{
    padding: 4px 8px;
    border: none;
}}
QHeaderView::section {{
    background-color: {DARK['surface']};
    color: {DARK['subtext']};
    padding: 7px 8px;
    border: none;
    border-right: 1px solid {DARK['overlay']};
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
}}
QHeaderView::section:last {{
    border-right: none;
}}

/* ── Inputs ────────────────────────────── */
QLineEdit {{
    background-color: {DARK['surface']};
    border: 1px solid {DARK['overlay']};
    border-radius: 5px;
    padding: 5px 10px;
    color: {DARK['text']};
    selection-background-color: {DARK['blue']};
    selection-color: {DARK['bg']};
}}
QLineEdit:focus {{
    border-color: {DARK['blue']};
}}
QComboBox {{
    background-color: {DARK['surface']};
    border: 1px solid {DARK['overlay']};
    border-radius: 5px;
    padding: 5px 10px;
    color: {DARK['text']};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox QAbstractItemView {{
    background-color: {DARK['surface']};
    color: {DARK['text']};
    selection-background-color: {DARK['blue']};
    selection-color: {DARK['bg']};
    border: 1px solid {DARK['overlay']};
}}

/* ── ScrollBars ────────────────────────── */
QScrollBar:vertical {{
    background-color: {DARK['bg2']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background-color: {DARK['overlay']};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {DARK['muted']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background-color: {DARK['bg2']};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background-color: {DARK['overlay']};
    border-radius: 4px;
    min-width: 30px;
}}

/* ── Status Bar ────────────────────────── */
QStatusBar {{
    background-color: {DARK['blue']};
    color: {DARK['bg3']};
    font-weight: 600;
    font-size: 12px;
    padding: 2px 8px;
}}
QStatusBar QLabel {{
    background-color: transparent;
    color: {DARK['bg3']};
    font-weight: 600;
}}

/* ── Labels / Frames ───────────────────── */
QLabel {{
    background-color: transparent;
}}
QFrame[frameShape="4"],
QFrame[frameShape="5"] {{
    color: {DARK['surface']};
}}

/* ── Group Box ─────────────────────────── */
QGroupBox {{
    border: 1px solid {DARK['surface']};
    border-radius: 6px;
    margin-top: 12px;
    padding: 8px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: {DARK['blue']};
}}

/* ── Splitter ──────────────────────────── */
QSplitter::handle {{
    background-color: {DARK['surface']};
}}
QSplitter::handle:horizontal {{ width: 2px; }}
QSplitter::handle:vertical   {{ height: 2px; }}

/* ── Progress Dialog ───────────────────── */
QProgressDialog {{
    background-color: {DARK['bg2']};
    color: {DARK['text']};
    border-radius: 8px;
}}
QProgressBar {{
    background-color: {DARK['surface']};
    border: none;
    border-radius: 4px;
    text-align: center;
    color: {DARK['bg']};
}}
QProgressBar::chunk {{
    background-color: {DARK['blue']};
    border-radius: 4px;
}}

/* ── Message Box ───────────────────────── */
QMessageBox {{
    background-color: {DARK['bg2']};
    color: {DARK['text']};
}}

/* ── List Widget ───────────────────────── */
QListWidget {{
    background-color: {DARK['bg2']};
    border: none;
    outline: none;
}}
QListWidget::item {{
    padding: 4px 8px;
    border-radius: 4px;
}}
QListWidget::item:selected {{
    background-color: {DARK['overlay']};
    color: {DARK['text']};
}}
"""

# Matplotlib dark theme settings
MPL_STYLE = {
    "figure.facecolor":   DARK["bg2"],
    "axes.facecolor":     DARK["bg2"],
    "axes.edgecolor":     DARK["surface"],
    "axes.labelcolor":    DARK["subtext"],
    "axes.titlecolor":    DARK["text"],
    "axes.grid":          True,
    "grid.color":         DARK["surface"],
    "grid.linestyle":     "--",
    "grid.alpha":         0.5,
    "text.color":         DARK["text"],
    "xtick.color":        DARK["muted"],
    "ytick.color":        DARK["muted"],
    "legend.facecolor":   DARK["surface"],
    "legend.edgecolor":   DARK["overlay"],
    "legend.labelcolor":  DARK["text"],
    "figure.autolayout":  True,
}

PROTOCOL_COLORS = {
    "TCP":   DARK["blue"],
    "UDP":   DARK["green"],
    "ICMP":  DARK["yellow"],
    "HTTP":  DARK["peach"],
    "HTTPS": DARK["mauve"],
    "DNS":   DARK["teal"],
    "ARP":   DARK["sky"],
    "OTHER": DARK["muted"],
}
