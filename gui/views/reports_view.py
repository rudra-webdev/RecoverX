"""
Reports & Security Audit View for RecoverX GUI
Enables viewing existing forensic investigation reports, inspecting cryptographic checksums,
and reviewing security audit results with export actions.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QSplitter,
    QFileDialog, QMessageBox, QTabWidget
)
from PySide6.QtCore import Qt
from pathlib import Path
import datetime
import shutil

from config import REPORTS_DIR, RECOVERED_DIR
from engine.security_auditor import SecurityAuditor
from utils.logging_config import logger

class ReportsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.report_files = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header Title
        title_box = QVBoxLayout()
        title = QLabel("Reports & Security Audit")
        title.setObjectName("headingLabel")
        desc = QLabel("Forensic case documentation, cryptographic hash records, and offline privacy audits")
        desc.setObjectName("subheadingLabel")
        title_box.addWidget(title)
        title_box.addWidget(desc)
        layout.addLayout(title_box)

        # Top Control Bar
        control_bar = QHBoxLayout()
        control_bar.setSpacing(10)

        self.btn_refresh = QPushButton("🔄 Refresh Reports")
        self.btn_refresh.clicked.connect(self.refresh_data)
        control_bar.addWidget(self.btn_refresh)

        self.btn_run_audit = QPushButton("🛡️ Run Live Security Audit")
        self.btn_run_audit.setObjectName("primaryButton")
        self.btn_run_audit.clicked.connect(self._run_live_audit)
        control_bar.addWidget(self.btn_run_audit)

        self.btn_export = QPushButton("📤 Export Selected Report...")
        self.btn_export.clicked.connect(self._export_selected_report)
        control_bar.addWidget(self.btn_export)

        control_bar.addStretch()
        layout.addLayout(control_bar)

        # Tab Widget: 1) Forensic Investigation Reports, 2) Security & Privacy Audit
        self.tabs = QTabWidget()

        # Tab 1: Forensic Reports
        tab_reports = QWidget()
        r_layout = QVBoxLayout(tab_reports)
        r_layout.setContentsMargins(12, 12, 12, 12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Table of Reports
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(4)
        self.reports_table.setHorizontalHeaderLabels(["REPORT FILENAME", "FORMAT", "SIZE", "GENERATED"])
        self.reports_table.horizontalHeader().setMinimumSectionSize(65)
        self.reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.reports_table.setColumnWidth(0, 220)
        self.reports_table.setColumnWidth(1, 100)
        self.reports_table.setColumnWidth(2, 75)
        self.reports_table.setColumnWidth(3, 135)
        self.reports_table.horizontalHeader().setStretchLastSection(True)
        self.reports_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.reports_table.verticalHeader().setVisible(False)
        self.reports_table.clicked.connect(self._on_report_selected)
        splitter.addWidget(self.reports_table)

        # Report Viewer
        self.report_viewer = QTextEdit()
        self.report_viewer.setReadOnly(True)
        self.report_viewer.setPlaceholderText("Select a report from the table to inspect...")
        splitter.addWidget(self.report_viewer)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        r_layout.addWidget(splitter)
        self.tabs.addTab(tab_reports, "📋 Forensic Investigation Reports")

        # Tab 2: Security & Privacy Audit
        tab_audit = QWidget()
        a_layout = QVBoxLayout(tab_audit)
        a_layout.setContentsMargins(12, 12, 12, 12)
        a_layout.setSpacing(10)

        self.audit_viewer = QTextEdit()
        self.audit_viewer.setReadOnly(True)
        a_layout.addWidget(self.audit_viewer)
        self.tabs.addTab(tab_audit, "🛡️ Security & Privacy Audit Logs")

        layout.addWidget(self.tabs, 1)

        self.refresh_data()

    def refresh_data(self):
        """Reloads reports and security audit logs."""
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
            dt = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            fmt = "Markdown Report" if f.suffix.lower() == ".md" else "JSON Artifact Dump"
            sz_str = f"{stat.st_size} B" if stat.st_size < 1024 else f"{stat.st_size/1024:.1f} KB"

            self.reports_table.setItem(row, 0, QTableWidgetItem(f.name))
            self.reports_table.setItem(row, 1, QTableWidgetItem(fmt))
            self.reports_table.setItem(row, 2, QTableWidgetItem(sz_str))
            self.reports_table.setItem(row, 3, QTableWidgetItem(dt))

        # Check for privacy_and_security_audit_report.md
        audit_file = REPORTS_DIR / "privacy_and_security_audit_report.md"
        if audit_file.exists():
            try:
                self.audit_viewer.setPlainText(audit_file.read_text(encoding="utf-8"))
            except Exception as e:
                self.audit_viewer.setPlainText(f"Failed to load audit file: {e}")
        else:
            self.audit_viewer.setPlainText("No audit log found. Click 'Run Live Security Audit' above to generate.")

    def _on_report_selected(self):
        row = self.reports_table.currentRow()
        if 0 <= row < len(self.report_files):
            target = self.report_files[row]
            try:
                content = target.read_text(encoding="utf-8", errors="replace")
                self.report_viewer.setPlainText(content)
            except Exception as e:
                self.report_viewer.setPlainText(f"Error reading report: {e}")

    def _run_live_audit(self):
        try:
            auditor = SecurityAuditor()
            results = auditor.run_audit()
            md_path = auditor.generate_markdown_report(results)
            json_path = auditor.generate_json_report(results)
            self.refresh_data()
            self.tabs.setCurrentIndex(1)
            QMessageBox.information(
                self,
                "Security Audit Complete",
                f"Comprehensive security audit completed successfully!\n\n"
                f"Status: {results.get('status')}\n"
                f"Network Sockets: {results.get('network_calls')}\n"
                f"Telemetry Endpoints: {results.get('telemetry_trackers')}\n\n"
                f"Audit Report Saved: {md_path.name}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Audit Error", f"Failed to execute security audit: {e}")

    def _export_selected_report(self):
        row = self.reports_table.currentRow()
        if row < 0 or row >= len(self.report_files):
            QMessageBox.warning(self, "No Report Selected", "Please select a report from the table to export.")
            return

        source_file = self.report_files[row]
        dest_file, _ = QFileDialog.getSaveFileName(
            self,
            "Export Forensic Report",
            source_file.name,
            "Markdown Files (*.md);;JSON Files (*.json);;All Files (*.*)"
        )
        if dest_file:
            try:
                shutil.copy2(source_file, dest_file)
                QMessageBox.information(self, "Report Exported", f"Report successfully exported to:\n{dest_file}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Failed to export report: {e}")

