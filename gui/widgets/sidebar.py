"""
Sidebar Navigation Widget for RecoverX GUI
Follows the Stitch reference design:
- Premium light layout (white background, slate border)
- Indigo brand logo and version badge
- 7 navigation items with active indigo pill and circular dot indicator
- Bottom "Offline Secured" green status card
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QButtonGroup,
    QFrame, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QPainter, QColor, QBrush, QPen

class NavButton(QPushButton):
    """Custom navigation button that draws a white indicator dot when active."""
    def __init__(self, text: str, icon_str: str, parent=None):
        super().__init__(parent)
        self.icon_str = icon_str
        self.label_text = text
        self.setObjectName("sidebarButton")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(40)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 14, 0)
        layout.setSpacing(10)

        self.icon_lbl = QLabel(icon_str)
        self.icon_lbl.setStyleSheet("font-size: 15px; background: transparent;")
        
        self.text_lbl = QLabel(text)
        self.text_lbl.setStyleSheet("font-size: 13px; font-weight: 600; background: transparent;")

        self.dot_lbl = QLabel("●")
        self.dot_lbl.setStyleSheet("font-size: 8px; color: #ffffff; background: transparent;")
        self.dot_lbl.setVisible(False)

        layout.addWidget(self.icon_lbl)
        layout.addWidget(self.text_lbl)
        layout.addStretch()
        layout.addWidget(self.dot_lbl)

    def setChecked(self, checked: bool):
        super().setChecked(checked)
        self.dot_lbl.setVisible(checked)
        if checked:
            self.text_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff; background: transparent;")
            self.icon_lbl.setStyleSheet("font-size: 15px; color: #ffffff; background: transparent;")
        else:
            self.text_lbl.setStyleSheet("font-size: 13px; font-weight: 600; color: #475569; background: transparent;")
            self.icon_lbl.setStyleSheet("font-size: 15px; color: #475569; background: transparent;")

class SidebarNavigation(QFrame):
    navigation_changed = Signal(int)  # Emits index of selected view (0..6)

    NAV_ITEMS = [
        ("Dashboard", "▦"),
        ("Recover Files", "⌕"),
        ("Android Recovery", "📱"),
        ("WhatsApp Recovery", "💬"),
        ("Recovery History", "🕒"),
        ("Reports & Audit", "📄"),
        ("Settings", "⚙")
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebarFrame")
        self.setFixedWidth(240)
        self._buttons = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 18, 14, 18)
        layout.setSpacing(6)

        # 1. Brand Logo & Header
        brand_container = QWidget()
        brand_layout = QHBoxLayout(brand_container)
        brand_layout.setContentsMargins(4, 0, 4, 14)
        brand_layout.setSpacing(10)

        # Brand Icon Badge
        logo_icon = QLabel("⌘")
        logo_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_icon.setFixedSize(38, 38)
        logo_icon.setStyleSheet("""
            background-color: #4f46e5;
            color: #ffffff;
            font-size: 20px;
            font-weight: bold;
            border-radius: 10px;
        """)
        brand_layout.addWidget(logo_icon)

        # Brand Titles
        text_box = QVBoxLayout()
        text_box.setSpacing(2)

        title_row = QHBoxLayout()
        title_row.setSpacing(6)
        title_lbl = QLabel("RecoverX")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #0f172a; letter-spacing: -0.2px;")
        
        badge_lbl = QLabel("PRO")
        badge_lbl.setStyleSheet("""
            background-color: #eef2ff;
            color: #4f46e5;
            font-size: 10px;
            font-weight: 800;
            padding: 2px 6px;
            border-radius: 4px;
        """)
        title_row.addWidget(title_lbl)
        title_row.addWidget(badge_lbl)
        title_row.addStretch()

        subtitle = QLabel("Forensic Recovery Engine")
        subtitle.setStyleSheet("font-size: 11px; color: #94a3b8; font-weight: 500;")

        text_box.addLayout(title_row)
        text_box.addWidget(subtitle)
        brand_layout.addLayout(text_box)

        layout.addWidget(brand_container)

        # 2. Navigation Items
        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)

        for idx, (label, icon_str) in enumerate(self.NAV_ITEMS):
            btn = NavButton(label, icon_str, self)
            if idx == 0:
                btn.setChecked(True)

            btn.clicked.connect(lambda checked=False, i=idx: self._on_btn_clicked(i))
            self.button_group.addButton(btn, idx)
            self._buttons.append(btn)
            layout.addWidget(btn)

        # Spacer to push footer down
        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # 3. Bottom Security Status Card
        footer_card = QFrame()
        footer_card.setStyleSheet("""
            background-color: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 10px;
        """)
        f_layout = QVBoxLayout(footer_card)
        f_layout.setContentsMargins(12, 10, 12, 10)
        f_layout.setSpacing(3)

        f_title_row = QHBoxLayout()
        f_icon = QLabel("🛡️")
        f_icon.setStyleSheet("font-size: 13px; background: transparent;")
        f_title = QLabel("Offline Secured")
        f_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #15803d; background: transparent;")
        f_dot = QLabel("•")
        f_dot.setStyleSheet("font-size: 12px; font-weight: 900; color: #22c55e; background: transparent;")

        f_title_row.addWidget(f_icon)
        f_title_row.addWidget(f_title)
        f_title_row.addWidget(f_dot)
        f_title_row.addStretch()

        f_desc = QLabel("Air-gapped • Software RO")
        f_desc.setStyleSheet("font-size: 11px; color: #166534; background: transparent;")

        f_layout.addLayout(f_title_row)
        f_layout.addWidget(f_desc)
        layout.addWidget(footer_card)

    def _on_btn_clicked(self, idx: int):
        for i, b in enumerate(self._buttons):
            b.setChecked(i == idx)
        self.navigation_changed.emit(idx)

    def set_active_index(self, index: int):
        if 0 <= index < len(self._buttons):
            for i, b in enumerate(self._buttons):
                b.setChecked(i == index)
