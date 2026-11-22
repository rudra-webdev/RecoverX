"""
Recovery History View for RecoverX GUI (Premium Light Redesign)
Provides full persistence and inspection of:
1. Historical forensic recovery sessions (retrieved from SQLite history database)
2. Raw forensic investigation report files (Markdown & JSON)
Allows reviewing session artifacts, cryptographic checksums, and reports directly inside the application.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QSplitter,
    QTabWidget
)
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import Qt, QUrl
from pathlib import Path
import datetime

from config import REPORTS_DIR, RECOVERED_DIR
from engine.history_manager import HistoryManager

class HistoryView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.report_files = []
        self.investigations = []
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

        clock_icon = QLabel("🕒")
        clock_icon.setStyleSheet("font-size: 20px;")
        title = QLabel("Recovery History & Audit Reports")
        title.setObjectName("headingLabel")
        title_row.addWidget(clock_icon)
        title_row.addWidget(title)
        title_row.addStretch()

        desc = QLabel("Review past forensic investigation sessions, carving summaries, and integrity verification reports")
        desc.setObjectName("subheadingLabel")

        title_box.addLayout(title_row)
        title_box.addWidget(desc)
        layout.addLayout(title_box)

        # Top Control Bar
        control_bar = QHBoxLayout()
        control_bar.setSpacing(10)

        self.btn_refresh = QPushButton("🔄 Refresh History")
        self.btn_refresh.clicked.connect(self.refresh_all)
        control_bar.addWidget(self.btn_refresh)

        self.btn_open_folder = QPushButton("📂 Open Reports Folder")
        self.btn_open_folder.clicked.connect(self._open_reports_folder)
        control_bar.addWidget(self.btn_open_folder)

        control_bar.addStretch()
        layout.addLayout(control_bar)

        # Tab Widget for Sessions vs Document Reports
        self.tabs = QTabWidget()

        # Tab 1: Investigation Sessions (Database)
        tab_sessions = QWidget()
        s_layout = QVBoxLayout(tab_sessions)
        s_layout.setContentsMargins(10, 10, 10, 10)

        sess_splitter = QSplitter(Qt.Orientation.Horizontal)
        sess_splitter.setChildrenCollapsible(False)

        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(7)
        self.sessions_table.setHorizontalHeaderLabels([
            "SESSION ID", "TIMESTAMP", "SOURCE MEDIA", "SCAN MODE", "DISCOVERED", "RECOVERED", "STATUS"
        ])
        self.sessions_table.horizontalHeader().setMinimumSectionSize(65)
        self.sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.sessions_table.setColumnWidth(0, 160)
        self.sessions_table.setColumnWidth(1, 135)
        self.sessions_table.setColumnWidth(2, 120)
        self.sessions_table.setColumnWidth(3, 160)
        self.sessions_table.setColumnWidth(4, 90)
        self.sessions_table.setColumnWidth(5, 90)
        self.sessions_table.setColumnWidth(6, 85)
        self.sessions_table.horizontalHeader().setStretchLastSection(True)
        self.sessions_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.sessions_table.verticalHeader().setVisible(False)
        self.sessions_table.clicked.connect(self._on_session_selected)
        sess_splitter.addWidget(self.sessions_table)

        # Session Detail Panel
        sess_detail_frame = QFrame()
        sess_detail_layout = QVBoxLayout(sess_detail_frame)
        sess_detail_layout.setContentsMargins(10, 10, 10, 10)
        sess_detail_layout.setSpacing(8)

        self.sess_detail_text = QTextEdit()
        self.sess_detail_text.setReadOnly(True)
        self.sess_detail_text.setPlaceholderText("Select an investigation session to view details and carved files...")
        sess_detail_layout.addWidget(self.sess_detail_text)

        sess_btn_box = QHBoxLayout()
        self.btn_open_session_dir = QPushButton("📂 Open Output Folder")
        self.btn_open_session_dir.setEnabled(False)
        self.btn_open_session_dir.clicked.connect(self._open_session_dir)
        self.btn_open_session_rep = QPushButton("📄 View Report")
        self.btn_open_session_rep.setEnabled(False)
        self.btn_open_session_rep.clicked.connect(self._open_session_rep)
        sess_btn_box.addWidget(self.btn_open_session_dir)
        sess_btn_box.addWidget(self.btn_open_session_rep)
        sess_detail_layout.addLayout(sess_btn_box)

        sess_splitter.addWidget(sess_detail_frame)
        sess_splitter.setStretchFactor(0, 3)
        sess_splitter.setStretchFactor(1, 2)
        s_layout.addWidget(sess_splitter)

        self.tabs.addTab(tab_sessions, "📋 Forensic Investigation Sessions")

        # Tab 2: Document Reports (Files in reports/)
        tab_reports = QWidget()
        r_layout = QVBoxLayout(tab_reports)
        r_layout.setContentsMargins(10, 10, 10, 10)

        rep_splitter = QSplitter(Qt.Orientation.Horizontal)
        rep_splitter.setChildrenCollapsible(False)

        # Table of Reports
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(4)
        self.reports_table.setHorizontalHeaderLabels(["REPORT FILENAME", "FORMAT", "SIZE", "DATE MODIFIED"])
        self.reports_table.horizontalHeader().setMinimumSectionSize(65)
        self.reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.reports_table.setColumnWidth(0, 220)
        self.reports_table.setColumnWidth(1, 95)
        self.reports_table.setColumnWidth(2, 75)
        self.reports_table.setColumnWidth(3, 135)
        self.reports_table.horizontalHeader().setStretchLastSection(True)
        self.reports_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.reports_table.verticalHeader().setVisible(False)
        self.reports_table.clicked.connect(self._on_report_selected)
        rep_splitter.addWidget(self.reports_table)

        # Report Viewer TextEdit
        self.report_viewer = QTextEdit()
        self.report_viewer.setReadOnly(True)
        self.report_viewer.setPlaceholderText("Select a report from the table to view its contents...")
        rep_splitter.addWidget(self.report_viewer)

        rep_splitter.setStretchFactor(0, 2)
        rep_splitter.setStretchFactor(1, 3)
        r_layout.addWidget(rep_splitter)

        self.tabs.addTab(tab_reports, "📄 Forensic Report Documents")

        layout.addWidget(self.tabs, 1)

        self._current_session_output = None
        self._current_session_report = None

        self.refresh_all()

    def refresh_all(self):
        self.refresh_sessions()
        self.refresh_reports()

    def refresh_sessions(self):
        self.sessions_table.setRowCount(0)
        self.investigations.clear()
        try:
            hist_mgr = HistoryManager()
            self.investigations = hist_mgr.get_all_investigations(limit=50)
            self.sessions_table.setRowCount(len(self.investigations))

            for row, inv in enumerate(self.investigations):
                self.sessions_table.setItem(row, 0, QTableWidgetItem(inv.get("session_id", "")))
                
                ts = inv.get("timestamp", "")
                try:
                    dt_obj = datetime.datetime.fromisoformat(ts)
                    time_str = dt_obj.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    time_str = ts[:16] if ts else ""
                self.sessions_table.setItem(row, 1, QTableWidgetItem(time_str))

                self.sessions_table.setItem(row, 2, QTableWidgetItem(inv.get("source_name", "")))
                self.sessions_table.setItem(row, 3, QTableWidgetItem(inv.get("scan_mode", "")))
                self.sessions_table.setItem(row, 4, QTableWidgetItem(str(inv.get("files_discovered", 0))))
                self.sessions_table.setItem(row, 5, QTableWidgetItem(str(inv.get("files_recovered", 0))))
                
                st_item = QTableWidgetItem(inv.get("status", "Completed"))
                st_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.sessions_table.setItem(row, 6, st_item)
        except Exception as e:
            self.sess_detail_text.setPlainText(f"Error loading investigation history: {e}")

    def refresh_reports(self):
        self.reports_table.setRowCount(0)
        self.report_files.clear()

        if not REPORTS_DIR.exists():
            return

        files = sorted(
            [f for f in REPORTS_DIR.iterdir() if f.is_file() and f.suffix.lower() in (".md", ".json") and not f.name.endswith(".db")],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        self.report_files = files

        self.reports_table.setRowCount(len(files))
        for row, f in enumerate(files):
            stat = f.stat()
            dt = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            fmt = "Markdown" if f.suffix.lower() == ".md" else "JSON Data"
            sz_str = f"{stat.st_size} B" if stat.st_size < 1024 else f"{stat.st_size/1024:.1f} KB"

            self.reports_table.setItem(row, 0, QTableWidgetItem(f.name))
            self.reports_table.setItem(row, 1, QTableWidgetItem(fmt))
            self.reports_table.setItem(row, 2, QTableWidgetItem(sz_str))
            self.reports_table.setItem(row, 3, QTableWidgetItem(dt))

    def _on_session_selected(self):
        row = self.sessions_table.currentRow()
        if 0 <= row < len(self.investigations):
            inv = self.investigations[row]
            self._current_session_output = inv.get("output_dir")
            self._current_session_report = inv.get("report_path")

            self.btn_open_session_dir.setEnabled(bool(self._current_session_output and Path(self._current_session_output).exists()))
            self.btn_open_session_rep.setEnabled(bool(self._current_session_report and Path(self._current_session_report).exists()))

            hist_mgr = HistoryManager()
            files = hist_mgr.get_investigation_files(inv["id"])

            lines = [
                f"SESSION ID        : {inv.get('session_id')}",
                f"TIMESTAMP         : {inv.get('timestamp')}",
                f"SOURCE NAME       : {inv.get('source_name')}",
                f"SOURCE PATH       : {inv.get('source_path')}",
                f"SOURCE TYPE       : {inv.get('source_type')}",
                f"SCAN MODE         : {inv.get('scan_mode')}",
                f"ENGINES USED      : {inv.get('engines_used')}",
                f"FILES DISCOVERED  : {inv.get('files_discovered', 0)}",
                f"FILES RECOVERED   : {inv.get('files_recovered', 0)} (Verified: {inv.get('files_validated', 0)})",
                f"TOTAL BYTES       : {inv.get('total_bytes', 0)} bytes",
                f"STATUS            : {inv.get('status')}",
                f"OUTPUT DIRECTORY  : {inv.get('output_dir')}",
                f"REPORT FILE       : {inv.get('report_path')}",
                "",
                "--- EXTRACTED FILES IN THIS SESSION ---"
            ]

            if files:
                for idx, f in enumerate(files, 1):
                    sz = f.get('size_bytes', 0)
                    sz_str = f"{sz} B" if sz < 1024 else f"{sz/1024:.1f} KB"
                    lines.append(f"{idx:02d}. {f.get('filename')} [{f.get('category')}] - {sz_str} - SHA-256: {f.get('sha256', '')[:16]}... [{f.get('status')}]")
            else:
                lines.append("No individual file records stored for this session.")

            self.sess_detail_text.setPlainText("\n".join(lines))

    def _open_session_dir(self):
        if self._current_session_output and Path(self._current_session_output).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._current_session_output))

    def _open_session_rep(self):
        if self._current_session_report and Path(self._current_session_report).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._current_session_report))

    def _on_report_selected(self):
        row = self.reports_table.currentRow()
        if 0 <= row < len(self.report_files):
            target = self.report_files[row]
            try:
                content = target.read_text(encoding="utf-8", errors="replace")
                self.report_viewer.setPlainText(content)
            except Exception as e:
                self.report_viewer.setPlainText(f"Error reading report: {e}")

    def _open_reports_folder(self):
        if REPORTS_DIR.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(REPORTS_DIR)))
