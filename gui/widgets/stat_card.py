"""
Stat Card Widget for RecoverX Dashboard (Premium Light Redesign)
Displays a key forensic metric card with icon badge, uppercase category tag,
large value, title, and descriptive subtitle matching the Stitch reference design.
"""
from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel
from PySide6.QtCore import Qt

class StatCard(QFrame):
    def __init__(
        self,
        title: str,
        value: str,
        subtitle: str = "",
        tag: str = "INFO",
        icon_str: str = "▦",
        accent_color: str = "#4f46e5",
        accent_bg: str = "#eef2ff",
        parent=None
    ):
        super().__init__(parent)
        self.setObjectName("cardFrame")
        self.accent_color = accent_color
        self.accent_bg = accent_bg
        self.tag_text = tag
        self.icon_str = icon_str
        self._init_ui(title, value, subtitle)

    def _init_ui(self, title: str, value: str, subtitle: str):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        # Top row: Icon badge + Tag
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.icon_badge = QLabel(self.icon_str)
        self.icon_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_badge.setFixedSize(26, 26)
        self.icon_badge.setStyleSheet(f"""
            background-color: {self.accent_bg};
            color: {self.accent_color};
            font-size: 13px;
            font-weight: bold;
            border-radius: 6px;
        """)

        self.tag_lbl = QLabel(self.tag_text)
        self.tag_lbl.setStyleSheet("""
            font-size: 10px;
            font-weight: 700;
            color: #94a3b8;
            letter-spacing: 0.5px;
        """)

        top_row.addWidget(self.icon_badge)
        top_row.addStretch()
        top_row.addWidget(self.tag_lbl)
        layout.addLayout(top_row)

        # Metric Title
        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #64748b;")
        layout.addWidget(self.title_lbl)

        # Metric Value
        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(f"font-size: 24px; font-weight: 800; color: {self.accent_color}; letter-spacing: -0.5px;")
        layout.addWidget(self.value_lbl)

        # Subtitle
        self.subtitle_lbl = QLabel(subtitle)
        self.subtitle_lbl.setStyleSheet("font-size: 11px; color: #94a3b8;")
        layout.addWidget(self.subtitle_lbl)

    def set_value(self, val: str):
        self.value_lbl.setText(val)

    def set_subtitle(self, sub: str):
        self.subtitle_lbl.setText(sub)
