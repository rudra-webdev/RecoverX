"""
Android Recovery & Investigation View for RecoverX GUI (Premium Light Redesign)
Graphical forensic interface for logical Android exploration via safe read-only ADB.
Explicitly discloses Scoped Storage and Hardware-Backed FBE limitations.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QScrollArea,
    QMessageBox, QCheckBox, QProgressBar
)
from PySide6.QtCore import Qt, QThread, Signal
from typing import Optional

from engine.device_manager import DeviceManager
from engine.android_scanner import AndroidScanner
from utils.adb import ADBClient
from config import DRY_RUN

class AndroidScanWorker(QThread):
    scan_complete = Signal(dict)
    scan_failed = Signal(str)

    def __init__(self, serial: Optional[str] = None, dry_run: bool = False, parent=None):
        super().__init__(parent)
        self.serial = serial
        self.dry_run = dry_run

    def run(self):
        try:
            adb = ADBClient(dry_run=self.dry_run)
            scanner = AndroidScanner(adb, dry_run=self.dry_run)
            res = scanner.scan_device(self.serial)
            self.scan_complete.emit(res)
        except Exception as e:
            self.scan_failed.emit(str(e))

class AndroidView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker: Optional[AndroidScanWorker] = None
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

        phone_icon = QLabel("📱")
        phone_icon.setStyleSheet("font-size: 20px;")
        title = QLabel("Android Recovery & Investigation")
        title.setObjectName("headingLabel")
        title_row.addWidget(phone_icon)
        title_row.addWidget(title)
        title_row.addStretch()

        desc = QLabel("Logical artifact auditing, media discovery, and security boundary evaluation")
        desc.setObjectName("subheadingLabel")

        title_box.addLayout(title_row)
        title_box.addWidget(desc)
        layout.addLayout(title_box)

        # 1. Technical Boundary Disclaimer Card
        notice_frame = QFrame()
        notice_frame.setStyleSheet("""
            background-color: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 10px;
        """)
        notice_layout = QVBoxLayout(notice_frame)
        notice_layout.setContentsMargins(16, 12, 16, 12)
        notice_layout.setSpacing(4)

        notice_title = QLabel("🛡️ ANDROID SECURITY BOUNDARIES & FORENSIC CONSTRAINTS")
        notice_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #0284c7;")

        notice_body = QLabel(
            "• Android 10-14 standard File-Based Encryption (FBE) evicts per-file encryption keys upon file deletion. Plaintext reconstruction from raw flash blocks without valid key material is technically infeasible via standard software.\n"
            "• Read-only ADB provides access to public shared storage (/storage/emulated/0). Raw block carving requires hardware chip-off.\n"
            "• RecoverX strictly adheres to non-destructive forensics: NO rooting, NO bootloader unlocking, and NO APK installation."
        )
        notice_body.setStyleSheet("font-size: 11px; color: #0369a1; line-height: 1.4;")

        notice_layout.addWidget(notice_title)
        notice_layout.addWidget(notice_body)
        layout.addWidget(notice_frame)

        # 2. Control Bar: Device Info + Action Buttons
        control_bar = QHBoxLayout()
        control_bar.setSpacing(12)

        self.lbl_device_status = QLabel("Checking ADB device status...")
        self.lbl_device_status.setStyleSheet("font-weight: 600; color: #0f172a;")
        control_bar.addWidget(self.lbl_device_status)

        control_bar.addStretch()

        self.chk_dry_run = QCheckBox("Dry-Run Simulation Mode")
        self.chk_dry_run.setChecked(DRY_RUN)
        control_bar.addWidget(self.chk_dry_run)

        self.btn_refresh = QPushButton("🔄 Refresh Device")
        self.btn_refresh.clicked.connect(self._refresh_device_info)
        control_bar.addWidget(self.btn_refresh)

        self.btn_start_scan = QPushButton("📱 Start Logical Scan")
        self.btn_start_scan.setObjectName("primaryButton")
        self.btn_start_scan.clicked.connect(self._start_scan)
        control_bar.addWidget(self.btn_start_scan)

        layout.addLayout(control_bar)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # 3. Content Splitter: Summary Cards & Detailed Table
        content_layout = QHBoxLayout()
        content_layout.setSpacing(14)

        # Left Column: Device Profile Details
        profile_frame = QFrame()
        profile_frame.setObjectName("cardFrame")
        profile_frame.setFixedWidth(280)
        p_layout = QVBoxLayout(profile_frame)
        p_layout.setContentsMargins(16, 16, 16, 16)
        p_layout.setSpacing(8)

        p_title = QLabel("DEVICE HARDWARE & OS PROFILE")
        p_title.setObjectName("statTitleLabel")
        p_layout.addWidget(p_title)

        self.profile_text = QTextEdit()
        self.profile_text.setReadOnly(True)
        self.profile_text.setPlaceholderText("Device information will appear here...")
        p_layout.addWidget(self.profile_text)

        content_layout.addWidget(profile_frame)

        # Right Column: Discovered Folders & Artifacts Table
        table_frame = QFrame()
        table_frame.setObjectName("cardFrame")
        t_layout = QVBoxLayout(table_frame)
        t_layout.setContentsMargins(16, 16, 16, 16)
        t_layout.setSpacing(8)

        t_title = QLabel("LOGICAL STORAGE ARTIFACTS & DIRECTORIES")
        t_title.setObjectName("statTitleLabel")
        t_layout.addWidget(t_title)

        self.artifacts_table = QTableWidget()
        self.artifacts_table.setColumnCount(4)
        self.artifacts_table.setHorizontalHeaderLabels(["NAME / SCOPE", "PATH", "ACCESSIBILITY", "FILE COUNT"])
        self.artifacts_table.horizontalHeader().setMinimumSectionSize(70)
        self.artifacts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.artifacts_table.setColumnWidth(0, 160)
        self.artifacts_table.setColumnWidth(1, 240)
        self.artifacts_table.setColumnWidth(2, 110)
        self.artifacts_table.setColumnWidth(3, 90)
        self.artifacts_table.horizontalHeader().setStretchLastSection(True)
        self.artifacts_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.artifacts_table.verticalHeader().setVisible(False)
        t_layout.addWidget(self.artifacts_table)

        content_layout.addWidget(table_frame, 1)
        layout.addLayout(content_layout)

        self._refresh_device_info()

    def _refresh_device_info(self):
        mgr = DeviceManager(dry_run=self.chk_dry_run.isChecked())
        devices = mgr.get_connected_devices()
        if not devices and not self.chk_dry_run.isChecked():
            self.lbl_device_status.setText("❌ No Android devices connected via USB.")
            self.profile_text.setPlainText("No device detected.\n\nEnsure USB debugging is enabled on your phone and connect via USB.")
            self.btn_start_scan.setEnabled(False)
            return

        self.btn_start_scan.setEnabled(True)
        prof = mgr.inspect_device()
        if prof.get("status") == "success":
            self.lbl_device_status.setText(f"🟢 Connected: {prof.get('manufacturer')} {prof.get('model')} (Android {prof.get('android_version')})")
            lines = [
                f"Manufacturer : {prof.get('manufacturer')}",
                f"Model        : {prof.get('model')} ({prof.get('device_codename')})",
                f"OS Flavor    : {prof.get('os_flavor', 'Android')}",
                f"Android OS   : {prof.get('android_version')} (SDK {prof.get('sdk_version')})",
                f"Build ID     : {prof.get('build_id')}",
                f"Security     : {prof.get('security_patch')}",
                f"Encryption   : {prof.get('fbe_status', 'FBE Active')}",
                f"Sandbox      : {prof.get('scoped_storage', 'Scoped Storage')}",
                f"Root Status  : {prof.get('root_status')}",
                f"Bootloader   : {prof.get('bootloader_status')}",
                f"SELinux      : {prof.get('selinux_mode')}",
                f"SD Card Mount: {prof.get('removable_sd_card_mount') or 'None (Internal only)'}"
            ]
            self.profile_text.setPlainText("\n".join(lines))
        else:
            self.lbl_device_status.setText(f"⚠️ {prof.get('message', 'Device state issue')}")

    def _start_scan(self):
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.btn_start_scan.setEnabled(False)
        self.lbl_device_status.setText("Executing logical read-only scan...")

        self.scan_worker = AndroidScanWorker(dry_run=self.chk_dry_run.isChecked(), parent=self)
        self.scan_worker.scan_complete.connect(self._on_scan_complete)
        self.scan_worker.scan_failed.connect(self._on_scan_failed)
        self.scan_worker.start()

    def _on_scan_complete(self, report: dict):
        self.progress_bar.setVisible(False)
        self.btn_start_scan.setEnabled(True)
        self.lbl_device_status.setText("Logical scan finished.")

        folders = report.get("media_findings", {}).get("folders", [])
        caches = report.get("cache_and_thumbnails", {}).get("discovered", [])
        total_rows = len(folders) + len(caches)

        self.artifacts_table.setRowCount(total_rows)
        row = 0
        for f in folders:
            self.artifacts_table.setItem(row, 0, QTableWidgetItem(f.get("name", "Media")))
            self.artifacts_table.setItem(row, 1, QTableWidgetItem(f.get("path", "")))
            self.artifacts_table.setItem(row, 2, QTableWidgetItem("Accessible" if f.get("accessible") else "Denied"))
            self.artifacts_table.setItem(row, 3, QTableWidgetItem(str(f.get("file_count", 0))))
            row += 1

        for c in caches:
            self.artifacts_table.setItem(row, 0, QTableWidgetItem("Cache / Thumbnail"))
            self.artifacts_table.setItem(row, 1, QTableWidgetItem(c.get("path", "")))
            self.artifacts_table.setItem(row, 2, QTableWidgetItem("Accessible"))
            self.artifacts_table.setItem(row, 3, QTableWidgetItem(str(c.get("file_count", 0))))
            row += 1

        QMessageBox.information(
            self,
            "Scan Completed",
            f"Android Logical Scan Finished.\n\n"
            f"Media Folders Checked: {len(folders)}\n"
            f"Cache Entries Discovered: {len(caches)}\n"
            f"Private Sandbox (/data/data): Isolated (Expected for Non-Root)"
        )

    def _on_scan_failed(self, err: str):
        self.progress_bar.setVisible(False)
        self.btn_start_scan.setEnabled(True)
        self.lbl_device_status.setText("Scan failed.")
        QMessageBox.critical(self, "Scan Error", f"Android scan failed: {err}")
