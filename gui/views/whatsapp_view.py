"""
WhatsApp Forensic Investigation View for RecoverX GUI (Premium Light Redesign)
Categorizes media, identifies unencrypted and encrypted (crypt14/15) databases,
inspects exported chat transcripts, and transparently reports cryptographic barriers.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QFileDialog,
    QMessageBox, QSplitter, QTabWidget, QLineEdit
)
from PySide6.QtCore import Qt
from pathlib import Path
from typing import Optional

from whatsapp.scanner import WhatsAppScanner
from whatsapp.chat_export_analyzer import WhatsAppChatExportAnalyzer
from whatsapp.database_analyzer import WhatsAppDatabaseAnalyzer
from whatsapp.backup_analyzer import WhatsAppBackupAnalyzer
from engine.report_generator import ReportGenerator
from utils.logging_config import logger

class WhatsAppView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_scan_results = None
        self.active_key_data = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header Title
        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        title_row = QHBoxLayout()
        title_row.setSpacing(8)

        wa_icon = QLabel("💬")
        wa_icon.setStyleSheet("font-size: 20px;")
        title = QLabel("WhatsApp Recovery & Forensics")
        title.setObjectName("headingLabel")
        title_row.addWidget(wa_icon)
        title_row.addWidget(title)
        title_row.addStretch()

        desc = QLabel("Media classification, database artifact identification, and chat export analysis")
        desc.setObjectName("subheadingLabel")

        title_box.addLayout(title_row)
        title_box.addWidget(desc)
        layout.addLayout(title_box)

        # Control Bar: Select Local Folder or Android
        control_bar = QHBoxLayout()
        control_bar.setSpacing(12)

        self.btn_select_dir = QPushButton("📁 Open Extracted WhatsApp Directory...")
        self.btn_select_dir.setObjectName("primaryButton")
        self.btn_select_dir.clicked.connect(self._select_whatsapp_dir)
        control_bar.addWidget(self.btn_select_dir)

        self.btn_select_key = QPushButton("🔑 Load Key File (Optional)...")
        self.btn_select_key.setStyleSheet("""
            QPushButton {
                background-color: #f1f5f9;
                color: #334155;
                font-weight: 600;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                padding: 6px 14px;
            }
            QPushButton:hover {
                background-color: #e2e8f0;
            }
        """)
        self.btn_select_key.clicked.connect(self._select_key_file)
        control_bar.addWidget(self.btn_select_key)

        self.btn_export_report = QPushButton("📄 Export Investigation Report...")
        self.btn_export_report.setStyleSheet("""
            QPushButton {
                background-color: #f1f5f9;
                color: #4338ca;
                font-weight: 600;
                border: 1px solid #c7d2fe;
                border-radius: 8px;
                padding: 6px 14px;
            }
            QPushButton:hover {
                background-color: #e0e7ff;
            }
        """)
        self.btn_export_report.clicked.connect(self._export_report)
        self.btn_export_report.setEnabled(False)
        control_bar.addWidget(self.btn_export_report)

        self.lbl_active_path = QLabel("No directory loaded. Open a local WhatsApp folder to audit.")
        self.lbl_active_path.setStyleSheet("color: #64748b; font-size: 12px; font-weight: 500;")
        control_bar.addWidget(self.lbl_active_path)

        control_bar.addStretch()
        layout.addLayout(control_bar)

        # Tabs: 1) Media Categories & Correlation, 2) Databases & Keys, 3) Exported Chats
        self.tabs = QTabWidget()

        # Tab 1: Media Breakdown & Correlation
        tab_media = QWidget()
        m_layout = QVBoxLayout(tab_media)
        m_layout.setContentsMargins(12, 12, 12, 12)
        self.media_table = QTableWidget()
        self.media_table.setColumnCount(4)
        self.media_table.setHorizontalHeaderLabels(["MEDIA CATEGORY", "TOTAL FILES", "SUPPORTED EXTENSIONS", "CORRELATION STATUS"])
        self.media_table.horizontalHeader().setMinimumSectionSize(70)
        self.media_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.media_table.setColumnWidth(0, 180)
        self.media_table.setColumnWidth(1, 100)
        self.media_table.setColumnWidth(2, 220)
        self.media_table.setColumnWidth(3, 200)
        self.media_table.horizontalHeader().setStretchLastSection(True)
        self.media_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.media_table.verticalHeader().setVisible(False)
        m_layout.addWidget(self.media_table)
        self.tabs.addTab(tab_media, "📸 Media & Correlation")

        # Tab 2: Databases & Cryptographic Keys
        tab_dbs = QWidget()
        db_layout = QVBoxLayout(tab_dbs)
        db_layout.setContentsMargins(12, 12, 12, 12)
        db_layout.setSpacing(10)

        db_notice = QLabel(
            "🔒 Cryptographic Note: Databases with .crypt14/.crypt15 extensions are AES-GCM encrypted. "
            "Without the hardware-bound key (/data/data/com.whatsapp/files/key) or 64-digit user key, "
            "decryption is impossible. RecoverX logs them honestly without false recovery claims."
        )
        db_notice.setWordWrap(True)
        db_notice.setStyleSheet("""
            font-size: 11px;
            color: #b45309;
            background-color: #fffbeb;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid #fde68a;
            line-height: 1.4;
        """)
        db_layout.addWidget(db_notice)

        self.db_table = QTableWidget()
        self.db_table.setColumnCount(6)
        self.db_table.setHorizontalHeaderLabels(["FILENAME", "SIZE", "FORMAT / CIPHER", "KEY STATUS", "FREELIST / WAL", "FORENSIC ASSESSMENT"])
        self.db_table.horizontalHeader().setMinimumSectionSize(70)
        self.db_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.db_table.setColumnWidth(0, 180)
        self.db_table.setColumnWidth(1, 80)
        self.db_table.setColumnWidth(2, 150)
        self.db_table.setColumnWidth(3, 110)
        self.db_table.setColumnWidth(4, 130)
        self.db_table.setColumnWidth(5, 220)
        self.db_table.horizontalHeader().setStretchLastSection(True)
        self.db_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.db_table.verticalHeader().setVisible(False)
        db_layout.addWidget(self.db_table)
        self.tabs.addTab(tab_dbs, "🗄️ Databases (crypt12/14/15)")

        # Tab 3: Exported Chats Transcript Viewer
        tab_chats = QWidget()
        chat_layout = QVBoxLayout(tab_chats)
        chat_layout.setContentsMargins(12, 12, 12, 12)

        chat_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.chats_table = QTableWidget()
        self.chats_table.setColumnCount(4)
        self.chats_table.setHorizontalHeaderLabels(["EXPORT FILENAME", "MESSAGES", "PARTICIPANTS", "ATTACHMENTS"])
        self.chats_table.horizontalHeader().setMinimumSectionSize(65)
        self.chats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.chats_table.setColumnWidth(0, 180)
        self.chats_table.setColumnWidth(1, 80)
        self.chats_table.setColumnWidth(2, 140)
        self.chats_table.setColumnWidth(3, 100)
        self.chats_table.horizontalHeader().setStretchLastSection(True)
        self.chats_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.chats_table.verticalHeader().setVisible(False)
        self.chats_table.clicked.connect(self._on_chat_selected)
        chat_splitter.addWidget(self.chats_table)

        self.chat_view_text = QTextEdit()
        self.chat_view_text.setReadOnly(True)
        self.chat_view_text.setPlaceholderText("Select an exported chat transcript to read...")
        chat_splitter.addWidget(self.chat_view_text)

        chat_layout.addWidget(chat_splitter)
        self.tabs.addTab(tab_chats, "💬 Exported Chat Transcripts")

        layout.addWidget(self.tabs, 1)

    def _select_whatsapp_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select WhatsApp Directory")
        if not dir_path:
            return

        target = Path(dir_path)
        self.lbl_active_path.setText(f"Loaded: {target.name} ({target})")

        scanner = WhatsAppScanner(target)
        results = scanner.scan(key_data=self.active_key_data)
        self.current_scan_results = results
        self._populate_results(results)
        self.btn_export_report.setEnabled(True)

    def _select_key_file(self):
        key_file, _ = QFileDialog.getOpenFileName(self, "Select WhatsApp Key File (158 bytes or 32 bytes)")
        if not key_file:
            return
        kp = Path(key_file)
        if kp.is_file():
            self.active_key_data = kp.read_bytes()
            key_inspect = WhatsAppBackupAnalyzer.inspect_key_file(self.active_key_data)
            QMessageBox.information(
                self,
                "WhatsApp Key Inspection",
                f"Key File: {kp.name}\n"
                f"Valid: {key_inspect.get('valid')}\n"
                f"Key Type: {key_inspect.get('key_type')}\n"
                f"Result: {key_inspect.get('message')}"
            )
            # Re-scan if directory is already loaded
            if self.current_scan_results and "target_root" in self.current_scan_results:
                scanner = WhatsAppScanner(Path(self.current_scan_results["target_root"]))
                results = scanner.scan(key_data=self.active_key_data)
                self.current_scan_results = results
                self._populate_results(results)

    def _export_report(self):
        if not self.current_scan_results:
            return
        rep = ReportGenerator()
        paths = rep.generate_report(self.current_scan_results, title="WhatsApp Forensic Investigation")
        QMessageBox.information(
            self,
            "Forensic Report Exported",
            f"Investigation reports generated successfully:\n\n"
            f"Markdown: {paths.get('markdown_report')}\n"
            f"JSON Dump: {paths.get('json_report')}"
        )

    def _populate_results(self, results: dict):
        # 1. Media
        media_summary = results.get("media_summary", {})
        categories = media_summary.get("categories", {})
        media_corr = results.get("media_correlation", {})
        ext_map = {
            "WhatsApp Images": "JPG, JPEG",
            "WhatsApp Video": "MP4, 3GP, MKV, AVI",
            "WhatsApp Audio": "MP3, M4A, WAV, OGG",
            "WhatsApp Voice Notes": "OPUS, OGG",
            "WhatsApp Documents": "PDF, DOCX, XLSX, TXT",
            "WhatsApp Stickers": "WebP",
            "WhatsApp Animated Gifs": "MP4, GIF",
            "WhatsApp Profile Photos": "JPG, JPEG"
        }

        self.media_table.setRowCount(len(categories))
        for row, (cat, cnt) in enumerate(categories.items()):
            self.media_table.setItem(row, 0, QTableWidgetItem(cat))
            self.media_table.setItem(row, 1, QTableWidgetItem(str(cnt)))
            self.media_table.setItem(row, 2, QTableWidgetItem(ext_map.get(cat, "Various")))
            status_text = f"Audited ({media_corr.get('database_referenced_count', 0)} DB-linked)" if cnt > 0 else "None found"
            self.media_table.setItem(row, 3, QTableWidgetItem(status_text))

        # 2. Databases
        databases_list = results.get("databases", [])
        if isinstance(databases_list, dict):
            databases_list = databases_list.get("findings", [])

        self.db_table.setRowCount(len(databases_list))
        for row, entry in enumerate(databases_list):
            db_info = entry.get("database_info", {})
            analysis = entry.get("analysis", {})
            backup_class = entry.get("backup_classification", {})

            fn = db_info.get("filename", "")
            sz = db_info.get("size_bytes", 0)
            sz_str = f"{sz} B" if sz < 1024 else f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/(1024*1024):.2f} MB"
            fmt = analysis.get("format", backup_class.get("cipher_suite", "Unknown"))
            
            # Key status
            key_status = backup_class.get("classification", "KEY_MISSING")
            if not analysis.get("is_encrypted", True):
                key_text = "N/A (Plaintext)"
            elif backup_class.get("key_status", {}).get("valid"):
                key_text = "Key Verified"
            else:
                key_text = "Missing Key"

            # Freelist / WAL
            sq_hdr = analysis.get("sqlite_header", {})
            freelist_cnt = sq_hdr.get("freelist_pages_count", 0)
            wal_companion = analysis.get("wal_companion", {})
            wal_frames = wal_companion.get("frame_count", 0)
            if not analysis.get("is_encrypted", True):
                fl_text = f"Freelist: {freelist_cnt} pgs | WAL: {wal_frames} frms"
            else:
                fl_text = "N/A (Encrypted)"

            assessment = (
                f"Plaintext SQLite: {analysis.get('statistics', {}).get('messages_count', 0)} msgs"
                if not analysis.get("is_encrypted", True)
                else f"Hardware Ciphertext ({backup_class.get('classification', 'ENCRYPTED')})"
            )

            self.db_table.setItem(row, 0, QTableWidgetItem(fn))
            self.db_table.setItem(row, 1, QTableWidgetItem(sz_str))
            self.db_table.setItem(row, 2, QTableWidgetItem(fmt))
            self.db_table.setItem(row, 3, QTableWidgetItem(key_text))
            self.db_table.setItem(row, 4, QTableWidgetItem(fl_text))
            self.db_table.setItem(row, 5, QTableWidgetItem(assessment))

        # 3. Chat Exports
        chats = results.get("chat_exports", [])
        self.chats_table.setRowCount(len(chats))
        for row, c in enumerate(chats):
            fn = Path(c.get("filepath", c.get("filename", "chat.txt"))).name
            msg_cnt = c.get("total_messages", c.get("parsed_messages", 0))
            participants = ", ".join(c.get("participants", []))
            att_cnt = len(c.get("attachments_referenced", []))

            self.chats_table.setItem(row, 0, QTableWidgetItem(fn))
            self.chats_table.setItem(row, 1, QTableWidgetItem(str(msg_cnt)))
            self.chats_table.setItem(row, 2, QTableWidgetItem(participants or "Unknown"))
            self.chats_table.setItem(row, 3, QTableWidgetItem(f"{att_cnt} files"))

    def _on_chat_selected(self):
        row = self.chats_table.currentRow()
        if not self.current_scan_results:
            return
        chats = self.current_scan_results.get("chat_exports", [])
        if 0 <= row < len(chats):
            fp = Path(chats[row].get("filepath", chats[row].get("path", "")))
            if fp.is_file():
                try:
                    self.chat_view_text.setPlainText(fp.read_text(encoding="utf-8", errors="replace"))
                except Exception as e:
                    self.chat_view_text.setPlainText(f"Error reading transcript: {e}")

