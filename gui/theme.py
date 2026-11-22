"""
RecoverX GUI Theme & Stylesheet Definition
Premium Modern Forensic Desktop Theme (Light Palette)
Primary background: White and light blue-grey (#f8fafc, #f1f5f9)
Brand / Action: Indigo & Purple (#4f46e5, #6366f1)
Accents: Cyan (#0ea5e9, #06b6d4), Emerald Green (#10b981), Amber (#f59e0b)
Border: Subtle Slate (#e2e8f0)
Typography: Clean, crisp Segoe UI / SF Pro / Inter
"""

LIGHT_THEME_QSS = """
QMainWindow {
    background-color: #f1f5f9;
    color: #0f172a;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

QWidget {
    background-color: #f1f5f9;
    color: #1e293b;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
}

/* Sidebar Styling */
QFrame#sidebarFrame {
    background-color: #ffffff;
    border-right: 1px solid #e2e8f0;
}

QFrame#sidebarFrame QWidget {
    background-color: transparent;
}

/* Rounded Cards */
QFrame#cardFrame {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
}

QFrame#cardFrame:hover {
    border: 1px solid #cbd5e1;
}

QFrame#innerCardFrame {
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
}

/* Typography */
QLabel#headingLabel {
    font-size: 22px;
    font-weight: 700;
    color: #0f172a;
    letter-spacing: -0.4px;
}

QLabel#subheadingLabel {
    font-size: 13px;
    color: #64748b;
}

QLabel#statValueLabel {
    font-size: 26px;
    font-weight: 800;
    color: #0f172a;
}

QLabel#statTitleLabel {
    font-size: 11px;
    text-transform: uppercase;
    color: #64748b;
    letter-spacing: 0.6px;
    font-weight: 700;
}

/* Standard Buttons */
QPushButton {
    background-color: #ffffff;
    color: #334155;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #f8fafc;
    border: 1px solid #cbd5e1;
    color: #0f172a;
}

QPushButton:pressed {
    background-color: #f1f5f9;
}

QPushButton:disabled {
    background-color: #f8fafc;
    color: #94a3b8;
    border: 1px solid #e2e8f0;
}

/* Primary Indigo Brand Button */
QPushButton#primaryButton {
    background-color: #4f46e5;
    color: #ffffff;
    border: 1px solid #4338ca;
}

QPushButton#primaryButton:hover {
    background-color: #4338ca;
    border: 1px solid #3730a3;
}

QPushButton#primaryButton:pressed {
    background-color: #3730a3;
}

QPushButton#primaryButton:disabled {
    background-color: #c7d2fe;
    color: #ffffff;
    border: 1px solid #c7d2fe;
}

/* Success Button */
QPushButton#successButton {
    background-color: #059669;
    color: #ffffff;
    border: 1px solid #047857;
}

QPushButton#successButton:hover {
    background-color: #047857;
}

QPushButton#successButton:disabled {
    background-color: #a7f3d0;
    color: #ffffff;
    border: 1px solid #a7f3d0;
}

/* Sidebar Navigation Buttons */
QPushButton#sidebarButton {
    background-color: transparent;
    color: #475569;
    border: none;
    border-radius: 8px;
    text-align: left;
    padding: 9px 14px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#sidebarButton:hover {
    background-color: #f1f5f9;
    color: #0f172a;
}

QPushButton#sidebarButton:checked {
    background-color: #4f46e5;
    color: #ffffff;
    font-weight: 700;
}

/* Filter Pill Buttons */
QPushButton#filterPill {
    background-color: #ffffff;
    color: #64748b;
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 5px 14px;
    font-size: 12px;
    font-weight: 600;
}

QPushButton#filterPill:hover {
    background-color: #f8fafc;
    color: #0f172a;
    border: 1px solid #cbd5e1;
}

QPushButton#filterPill:checked {
    background-color: #4f46e5;
    color: #ffffff;
    border: 1px solid #4338ca;
}

/* Form Controls */
QLineEdit, QComboBox {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 13px;
    selection-background-color: #e0e7ff;
    selection-color: #3730a3;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid #6366f1;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid #e2e8f0;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    selection-background-color: #eef2ff;
    selection-color: #4f46e5;
    padding: 4px;
}

/* Tables */
QTableView, QTableWidget {
    background-color: #ffffff;
    color: #1e293b;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    gridline-color: #f1f5f9;
    selection-background-color: #eef2ff;
    selection-color: #312e81;
}

QHeaderView::section {
    background-color: #f8fafc;
    color: #64748b;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border: none;
    border-bottom: 1px solid #e2e8f0;
    border-right: 1px solid #f1f5f9;
    padding: 8px 10px;
}

QHeaderView::section:hover {
    background-color: #f1f5f9;
    color: #0f172a;
}

/* Text Editors & Viewers */
QTextEdit {
    background-color: #ffffff;
    color: #1e293b;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 10px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.4;
}

/* Progress Bar */
QProgressBar {
    background-color: #e2e8f0;
    border: none;
    border-radius: 6px;
    height: 10px;
    text-align: right;
    font-size: 10px;
    color: transparent;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6366f1, stop:1 #4f46e5);
    border-radius: 6px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #f8fafc;
    width: 10px;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::handle:vertical {
    background: #cbd5e1;
    border-radius: 4px;
    min-height: 24px;
}

QScrollBar::handle:vertical:hover {
    background: #94a3b8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: #f8fafc;
    height: 10px;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::handle:horizontal {
    background: #cbd5e1;
    border-radius: 4px;
    min-width: 24px;
}

QScrollBar::handle:horizontal:hover {
    background: #94a3b8;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    height: 0px;
}

/* Checkboxes */
QCheckBox {
    color: #334155;
    font-size: 13px;
    font-weight: 500;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    background-color: #ffffff;
}

QCheckBox::indicator:hover {
    border: 1px solid #6366f1;
}

QCheckBox::indicator:checked {
    background-color: #4f46e5;
    border: 1px solid #4338ca;
    image: none;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    background-color: #ffffff;
    top: -1px;
}

QTabBar::tab {
    background-color: #f1f5f9;
    color: #64748b;
    padding: 8px 18px;
    font-weight: 600;
    border: 1px solid #e2e8f0;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 4px;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #4f46e5;
    border-bottom: 2px solid #ffffff;
}

QTabBar::tab:hover:!selected {
    background-color: #e2e8f0;
    color: #0f172a;
}
"""
