"""
Custom Donut Chart Widget for File Types Distribution (Light Theme)
Renders a smooth circular donut chart with center file count and a color-coded legend.
"""
from PySide6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QPainter, QColor, QPen, QBrush, QFont
from typing import Dict

class DonutCanvas(QWidget):
    def __init__(self, counts: Dict[str, int], parent=None):
        super().__init__(parent)
        self.counts = counts
        self.setFixedSize(130, 130)

        # Category colors matching Stitch reference
        self.color_map = {
            "Images": QColor("#3b82f6"),      # Blue
            "Documents": QColor("#06b6d4"),   # Cyan
            "Archives": QColor("#f59e0b"),    # Amber
            "Videos": QColor("#10b981"),      # Emerald
            "Audio": QColor("#f43f5e"),       # Rose
            "Other": QColor("#8b5cf6")        # Violet
        }

    def set_counts(self, counts: Dict[str, int]):
        self.counts = counts
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(10, 10, 110, 110)
        total = sum(self.counts.values())

        if total == 0:
            # Draw placeholder grey ring
            pen = QPen(QColor("#e2e8f0"), 14)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawArc(rect, 0, 360 * 16)

            # Draw center text
            painter.setPen(QColor("#94a3b8"))
            font = QFont("Segoe UI", 11, QFont.Weight.Bold)
            painter.setFont(font)
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "0\nFILES")
            return

        start_angle = 90 * 16
        for cat, cnt in self.counts.items():
            if cnt <= 0:
                continue
            span_angle = int((cnt / total) * 360 * 16)
            pen = QPen(self.color_map.get(cat, QColor("#cbd5e1")), 14)
            pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            painter.setPen(pen)
            painter.drawArc(rect, start_angle, -span_angle)
            start_angle -= span_angle

        # Draw Center Count Text
        painter.setPen(QColor("#0f172a"))
        font_num = QFont("Segoe UI", 16, QFont.Weight.ExtraBold)
        painter.setFont(font_num)

        center_rect_num = QRectF(10, 36, 110, 30)
        painter.drawText(center_rect_num, Qt.AlignmentFlag.AlignCenter, str(total))

        font_sub = QFont("Segoe UI", 9, QFont.Weight.Bold)
        painter.setFont(font_sub)
        painter.setPen(QColor("#64748b"))
        center_rect_sub = QRectF(10, 64, 110, 20)
        painter.drawText(center_rect_sub, Qt.AlignmentFlag.AlignCenter, "FILES")

class FileTypesDonutWidget(QWidget):
    def __init__(self, counts: Dict[str, int], parent=None):
        super().__init__(parent)
        self.counts = counts
        self._init_ui()

    @property
    def total_files(self) -> int:
        return sum(self.counts.values())

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(18)

        # Canvas on left
        self.canvas = DonutCanvas(self.counts, self)
        layout.addWidget(self.canvas)

        # Legend on right
        self.legend_layout = QVBoxLayout()
        self.legend_layout.setSpacing(6)
        self.legend_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(self.legend_layout)

        self._rebuild_legend()

    def _rebuild_legend(self):
        # Clear existing
        while self.legend_layout.count():
            item = self.legend_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        total = sum(self.counts.values())
        categories = ["Images", "Documents", "Archives", "Videos", "Audio"]

        color_hex = {
            "Images": "#3b82f6",
            "Documents": "#06b6d4",
            "Archives": "#f59e0b",
            "Videos": "#10b981",
            "Audio": "#f43f5e"
        }

        for cat in categories:
            cnt = self.counts.get(cat, 0)
            pct = int((cnt / total) * 100) if total > 0 else 0

            row = QHBoxLayout()
            row.setSpacing(8)

            # Color square
            sq = QLabel()
            sq.setFixedSize(10, 10)
            sq.setStyleSheet(f"background-color: {color_hex[cat]}; border-radius: 2px;")
            row.addWidget(sq)

            # Name
            lbl_name = QLabel(cat)
            lbl_name.setStyleSheet("font-size: 11px; font-weight: 600; color: #334155; min-width: 70px;")
            row.addWidget(lbl_name)

            # Stat
            lbl_stat = QLabel(f"{cnt} ({pct}%)")
            lbl_stat.setStyleSheet("font-size: 11px; color: #64748b; font-weight: 500;")
            row.addStretch()
            row.addWidget(lbl_stat)

            self.legend_layout.addLayout(row)

    def update_data(self, counts: Dict[str, int]):
        self.counts = counts
        self.canvas.set_counts(counts)
        self._rebuild_legend()

