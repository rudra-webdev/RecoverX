"""
File Preview Panel Widget for RecoverX GUI (Premium Light Redesign)
Renders image thumbnails (via Pillow / QPixmap), archive manifests, plaintext samples,
and structured forensic metadata inspectors.
Adheres strictly to forensic integrity: disclaims preview as proof of defragmented recovery.
"""
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QLabel, QTextEdit, QScrollArea, QWidget, QSizePolicy
)
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtCore import Qt
import io
import zipfile
from PIL import Image

class PreviewPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("cardFrame")
        self.setFixedWidth(320)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("FILE INSPECTOR & PREVIEW")
        title.setObjectName("statTitleLabel")
        layout.addWidget(title)

        # Image Preview Area
        self.preview_image_label = QLabel()
        self.preview_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_image_label.setFixedHeight(180)
        self.preview_image_label.setStyleSheet("""
            background-color: #f8fafc;
            border: 1px dashed #cbd5e1;
            border-radius: 8px;
            color: #64748b;
            font-size: 12px;
            font-weight: 600;
        """)
        self.preview_image_label.setText("No File Selected")
        layout.addWidget(self.preview_image_label)

        # Forensic Integrity Disclaimer Notice
        self.disclaimer_label = QLabel(
            "⚠️ Forensic Disclaimer: Thumbnail preview is generated for visual identification only. "
            "It does not constitute proof of complete defragmentation or integrity."
        )
        self.disclaimer_label.setWordWrap(True)
        self.disclaimer_label.setStyleSheet("""
            font-size: 10px;
            color: #b45309;
            background-color: #fffbeb;
            padding: 8px;
            border-radius: 6px;
            border: 1px solid #fde68a;
            line-height: 1.3;
        """)
        layout.addWidget(self.disclaimer_label)

        # Metadata text area
        self.meta_text = QTextEdit()
        self.meta_text.setReadOnly(True)
        self.meta_text.setPlaceholderText("Select a file from the table to inspect metadata...")
        layout.addWidget(self.meta_text)

    def display_file(self, item_entry):
        """Displays thumbnail and metadata for the selected item entry."""
        if not item_entry:
            self.clear_preview()
            return

        raw = item_entry.raw
        cat = item_entry.category
        ext = item_entry.extension.lower()

        # 1. Render thumbnail preview if Image
        data_bytes = raw.get("data")
        rendered_preview = False

        if cat == "Images" and data_bytes and len(data_bytes) > 0:
            # Try QImage first
            try:
                qimg = QImage()
                if qimg.loadFromData(data_bytes):
                    pix = QPixmap.fromImage(qimg)
                    scaled_pix = pix.scaled(
                        self.preview_image_label.width() - 20,
                        self.preview_image_label.height() - 20,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation
                    )
                    self.preview_image_label.setPixmap(scaled_pix)
                    rendered_preview = True
            except Exception:
                rendered_preview = False

            # Fallback to Pillow if QImage failed
            if not rendered_preview:
                try:
                    with Image.open(io.BytesIO(data_bytes)) as pil_img:
                        pil_img.thumbnail((260, 160))
                        with io.BytesIO() as buf:
                            pil_img.save(buf, format="PNG")
                            qimg = QImage()
                            if qimg.loadFromData(buf.getvalue()):
                                pix = QPixmap.fromImage(qimg)
                                self.preview_image_label.setPixmap(pix)
                                rendered_preview = True
                except Exception:
                    rendered_preview = False

        if not rendered_preview:
            icon_map = {
                "Videos": "🎬 [Video Stream]",
                "Audio": "🎵 [Audio Stream]",
                "Documents": "📄 [Document]",
                "Archives": "📦 [Compressed Archive]",
                "Databases": "🗄️ [Database]"
            }
            display_icon = icon_map.get(cat, f"📁 [{item_entry.category}]")
            self.preview_image_label.setText(f"{display_icon}\nNo visual thumbnail preview")

        # 2. Render metadata text
        details = raw.get("details", {})
        meta_lines = [
            f"Filename    : {item_entry.filename}",
            f"Type        : {item_entry.extension}",
            f"Category    : {item_entry.category}",
            f"Size        : {item_entry.formatted_size} ({item_entry.size_bytes} bytes)",
            f"Offset      : 0x{raw.get('offset', 0):08X}",
            f"Status      : {item_entry.status_string}",
            f"Confidence  : {int(item_entry.confidence * 100)}%",
            f"Engine      : {item_entry.backend}",
            f"SHA-256     :\n{item_entry.sha256}",
        ]

        # Inspect archives safely for contents
        if ext in ("zip", "docx", "xlsx", "pptx") and data_bytes and len(data_bytes) > 0:
            try:
                with zipfile.ZipFile(io.BytesIO(data_bytes)) as zf:
                    namelist = zf.namelist()[:10]
                    meta_lines.append(f"\n--- Archive Manifest ({len(zf.namelist())} entries) ---")
                    for name in namelist:
                        meta_lines.append(f"  • {name}")
                    if len(zf.namelist()) > 10:
                        meta_lines.append(f"  ... and {len(zf.namelist()) - 10} more items")
            except Exception:
                pass

        # Inspect text files safely for preview snippet
        if ext == "txt" and data_bytes and len(data_bytes) > 0:
            try:
                snippet = data_bytes[:300].decode("utf-8", errors="replace")
                meta_lines.append("\n--- Text Content Preview (First 300 bytes) ---")
                meta_lines.append(snippet)
            except Exception:
                pass

        if details:
            meta_lines.append("\n--- Format Details ---")
            for k, v in details.items():
                meta_lines.append(f"{k}: {v}")

        if item_entry.fragmented:
            meta_lines.append("\n[!] WARNING: Potential file fragmentation detected.")

        self.meta_text.setPlainText("\n".join(meta_lines))

    def clear_preview(self):
        self.preview_image_label.clear()
        self.preview_image_label.setText("No File Selected")
        self.meta_text.clear()
