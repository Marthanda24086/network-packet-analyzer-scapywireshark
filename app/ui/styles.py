"""
Stylesheets and theme definitions for NetScope UI.
Professional dark network monitoring aesthetic.
"""

DARK_THEME_QSS = """
QMainWindow, QDialog {
    background-color: #0f172a;
    color: #f8fafc;
}

QWidget {
    background-color: #0f172a;
    color: #f8fafc;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

QGroupBox {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    margin-top: 12px;
    font-weight: bold;
    color: #38bdf8;
    padding: 12px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
}

QLabel {
    color: #e2e8f0;
}

QPushButton {
    background-color: #2563eb;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #3b82f6;
}

QPushButton:pressed {
    background-color: #1d4ed8;
}

QPushButton:disabled {
    background-color: #475569;
    color: #94a3b8;
}

QPushButton#btnStart {
    background-color: #16a34a;
}
QPushButton#btnStart:hover {
    background-color: #22c55e;
}

QPushButton#btnStop {
    background-color: #dc2626;
}
QPushButton#btnStop:hover {
    background-color: #ef4444;
}

QLineEdit, QComboBox, QSpinBox {
    background-color: #1e293b;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 6px 10px;
    color: #f8fafc;
    selection-background-color: #2563eb;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #38bdf8;
}

QTableWidget, QTreeView, QTextEdit {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    gridline-color: #334155;
    color: #f8fafc;
}

QTableWidget::item:selected, QTreeView::item:selected {
    background-color: #1d4ed8;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 8px;
    font-weight: bold;
    border: none;
    border-bottom: 2px solid #334155;
}

QTabWidget::pane {
    border: 1px solid #334155;
    background-color: #1e293b;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 10px 20px;
    font-weight: 600;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background-color: #1e293b;
    color: #38bdf8;
    border-bottom: 2px solid #38bdf8;
}

QStatusBar {
    background-color: #1e293b;
    color: #94a3b8;
    border-top: 1px solid #334155;
}

QSplitter::handle {
    background-color: #334155;
    height: 4px;
    width: 4px;
}
"""
