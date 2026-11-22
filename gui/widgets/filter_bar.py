"""
Filter Bar Widget for RecoverX File Results (Premium Light Redesign)
Provides category pill buttons, status filter dropdown, search query box, and selection controls.
"""
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QPushButton, QComboBox, QLineEdit, QLabel, QButtonGroup
)
from PySide6.QtCore import Signal, Qt

class FilterBar(QWidget):
    category_changed = Signal(str)
    status_changed = Signal(str)
    search_changed = Signal(str)
    select_all_clicked = Signal(bool)

    CATEGORIES = ["All", "Images", "Videos", "Audio", "Documents", "Archives"]
    STATUSES = ["All", "Recoverable", "Partially recoverable", "Invalid or incomplete"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 8)
        layout.setSpacing(8)

        # Category Buttons Group as Pills
        self.cat_group = QButtonGroup(self)
        self.cat_group.setExclusive(True)

        for idx, cat in enumerate(self.CATEGORIES):
            btn = QPushButton(cat)
            btn.setObjectName("filterPill")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if idx == 0:
                btn.setChecked(True)
            btn.clicked.connect(lambda checked=False, c=cat: self.category_changed.emit(c))
            self.cat_group.addButton(btn, idx)
            layout.addWidget(btn)

        layout.addSpacing(8)

        # Status Filter Dropdown
        lbl_status = QLabel("Status:")
        lbl_status.setStyleSheet("font-size: 12px; font-weight: 600; color: #64748b;")
        layout.addWidget(lbl_status)

        self.status_combo = QComboBox()
        self.status_combo.addItems(self.STATUSES)
        self.status_combo.currentTextChanged.connect(self.status_changed.emit)
        layout.addWidget(self.status_combo)

        layout.addSpacing(8)

        # Search Box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Filter by filename or extension...")
        self.search_box.textChanged.connect(self.search_changed.emit)
        layout.addWidget(self.search_box)

        # Select All / None Buttons
        self.btn_select_all = QPushButton("Select All")
        self.btn_select_all.clicked.connect(lambda: self.select_all_clicked.emit(True))
        self.btn_deselect = QPushButton("Deselect")
        self.btn_deselect.clicked.connect(lambda: self.select_all_clicked.emit(False))

        layout.addWidget(self.btn_select_all)
        layout.addWidget(self.btn_deselect)
