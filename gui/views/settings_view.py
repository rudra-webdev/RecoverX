"""
Settings View for RecoverX GUI (Premium Light Redesign)
Configures offline isolation, ADB allowlist enforcement, external engine paths (PhotoRec, TSK),
and local output destinations.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QLineEdit, QCheckBox, QFileDialog, QMessageBox, QScrollArea
)
from PySide6.QtCore import Qt
from pathlib import Path

from config import (
    RECOVERED_DIR, REPORTS_DIR, OFFLINE_MODE, DRY_RUN, ENFORCE_ADB_ALLOWLIST, ADB_PATH,
    PHOTOREC_PATH, TSK_BIN_DIR, save_user_settings, load_user_settings
)
import config
from integrations.photorec.runner import PhotoRecIntegration
from integrations.sleuthkit.runner import TheSleuthKitIntegration
from utils.network_guard import is_offline_mode_active

class SettingsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # Header Title
        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        title_row = QHBoxLayout()
        title_row.setSpacing(8)

        settings_icon = QLabel("⚙")
        settings_icon.setStyleSheet("font-size: 20px;")
        title = QLabel("Settings & Privacy Safeguards")
        title.setObjectName("headingLabel")
        title_row.addWidget(settings_icon)
        title_row.addWidget(title)
        title_row.addStretch()

        desc = QLabel("Forensic safety controls, offline enforcement, and external engine toolpaths")
        desc.setObjectName("subheadingLabel")

        title_box.addLayout(title_row)
        title_box.addWidget(desc)
        main_layout.addLayout(title_box)

        # Scroll Area for Settings Sections
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # 1. Privacy & Network Security Card
        sec_card = QFrame()
        sec_card.setObjectName("cardFrame")
        sec_layout = QVBoxLayout(sec_card)
        sec_layout.setContentsMargins(18, 16, 18, 16)
        sec_layout.setSpacing(12)

        sec_title = QLabel("NETWORK PRIVACY & FORENSIC ISOLATION")
        sec_title.setObjectName("statTitleLabel")
        sec_layout.addWidget(sec_title)

        self.chk_offline = QCheckBox("Enforce Strict Offline Mode (Block all outbound network socket connections)")
        self.chk_offline.setChecked(OFFLINE_MODE)
        self.chk_offline.setEnabled(False)  # Permanently enforced for privacy
        sec_layout.addWidget(self.chk_offline)

        self.chk_allowlist = QCheckBox("Enforce Strict ADB Command Allowlist (Reject unapproved shell commands)")
        self.chk_allowlist.setChecked(ENFORCE_ADB_ALLOWLIST)
        self.chk_allowlist.setEnabled(False)  # Permanently enforced for device safety
        sec_layout.addWidget(self.chk_allowlist)

        self.chk_dry_run_default = QCheckBox("Enable Dry-Run by default (Preview commands without physical device execution)")
        self.chk_dry_run_default.setChecked(DRY_RUN)
        sec_layout.addWidget(self.chk_dry_run_default)

        layout.addWidget(sec_card)

        # 2. External Engine Paths Card
        eng_card = QFrame()
        eng_card.setObjectName("cardFrame")
        eng_layout = QVBoxLayout(eng_card)
        eng_layout.setContentsMargins(18, 16, 18, 16)
        eng_layout.setSpacing(12)

        eng_title = QLabel("EXTERNAL RECOVERY ENGINE CONFIGURATION")
        eng_title.setObjectName("statTitleLabel")
        eng_layout.addWidget(eng_title)

        # PhotoRec Path
        pr_box = QVBoxLayout()
        pr_lbl = QLabel("PhotoRec Executable Path (photorec_win.exe):")
        pr_lbl.setStyleSheet("font-weight: 600; color: #334155;")
        pr_row = QHBoxLayout()
        self.pr_path_edit = QLineEdit()
        self.pr_integration = PhotoRecIntegration()
        if self.pr_integration.binary_path:
            self.pr_path_edit.setText(self.pr_integration.binary_path)
        self.btn_browse_pr = QPushButton("Browse...")
        self.btn_browse_pr.clicked.connect(self._browse_photorec)
        self.btn_check_pr = QPushButton("Check Status")
        self.btn_check_pr.clicked.connect(self._check_photorec)
        pr_row.addWidget(self.pr_path_edit)
        pr_row.addWidget(self.btn_browse_pr)
        pr_row.addWidget(self.btn_check_pr)
        pr_box.addWidget(pr_lbl)
        pr_box.addLayout(pr_row)
        eng_layout.addLayout(pr_box)

        # TSK Tools Path
        tsk_box = QVBoxLayout()
        tsk_lbl = QLabel("The Sleuth Kit (TSK) Binaries Directory (containing fls.exe, icat.exe):")
        tsk_lbl.setStyleSheet("font-weight: 600; color: #334155;")
        tsk_row = QHBoxLayout()
        self.tsk_path_edit = QLineEdit()
        self.tsk_integration = TheSleuthKitIntegration()
        if self.tsk_integration.bin_dir:
            self.tsk_path_edit.setText(self.tsk_integration.bin_dir)
        self.btn_browse_tsk = QPushButton("Browse...")
        self.btn_browse_tsk.clicked.connect(self._browse_tsk)
        self.btn_check_tsk = QPushButton("Check Status")
        self.btn_check_tsk.clicked.connect(self._check_tsk)
        tsk_row.addWidget(self.tsk_path_edit)
        tsk_row.addWidget(self.btn_browse_tsk)
        tsk_row.addWidget(self.btn_check_tsk)
        tsk_box.addWidget(tsk_lbl)
        tsk_box.addLayout(tsk_row)
        eng_layout.addLayout(tsk_box)

        layout.addWidget(eng_card)

        # 3. Output Folders Card
        out_card = QFrame()
        out_card.setObjectName("cardFrame")
        out_layout = QVBoxLayout(out_card)
        out_layout.setContentsMargins(18, 16, 18, 16)
        out_layout.setSpacing(12)

        out_title = QLabel("LOCAL FORENSIC REPOSITORY DIRECTORIES")
        out_title.setObjectName("statTitleLabel")
        out_layout.addWidget(out_title)

        out_rec = QHBoxLayout()
        out_rec.addWidget(QLabel("Default Recovered Files Destination:"))
        self.lbl_rec_path = QLabel(str(RECOVERED_DIR))
        self.lbl_rec_path.setStyleSheet("font-family: monospace; color: #4f46e5; font-weight: 600;")
        out_rec.addWidget(self.lbl_rec_path)
        out_rec.addStretch()
        out_layout.addLayout(out_rec)

        out_rep = QHBoxLayout()
        out_rep.addWidget(QLabel("Default Investigation Reports Directory:"))
        self.lbl_rep_path = QLabel(str(REPORTS_DIR))
        self.lbl_rep_path.setStyleSheet("font-family: monospace; color: #4f46e5; font-weight: 600;")
        out_rep.addWidget(self.lbl_rep_path)
        out_rep.addStretch()
        out_layout.addLayout(out_rep)

        layout.addWidget(out_card)

        # 4. Save Button
        self.btn_save = QPushButton("Save Settings")
        self.btn_save.setObjectName("primaryButton")
        self.btn_save.clicked.connect(self._save_settings)
        layout.addWidget(self.btn_save, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addStretch()
        scroll.setWidget(content)
        main_layout.addWidget(scroll)

    def _browse_photorec(self):
        f, _ = QFileDialog.getOpenFileName(
            self,
            "Select PhotoRec Executable",
            "",
            "Executable Files (*.exe);;All Files (*.*)"
        )
        if f:
            self.pr_path_edit.setText(f)

    def _check_photorec(self):
        path = self.pr_path_edit.text().strip()
        pr = PhotoRecIntegration(binary_path=path if path else None)
        status = pr.get_status()
        if status["is_available"]:
            QMessageBox.information(
                self,
                "PhotoRec Detected",
                f"PhotoRec executable is valid!\n\nVersion: {status.get('version')}\nPath: {status.get('binary_path')}"
            )
        else:
            QMessageBox.warning(
                self,
                "PhotoRec Not Found",
                f"PhotoRec is not available:\n{status.get('installation_notice')}"
            )

    def _browse_tsk(self):
        d = QFileDialog.getExistingDirectory(self, "Select TSK Binaries Directory")
        if d:
            self.tsk_path_edit.setText(d)

    def _check_tsk(self):
        d = self.tsk_path_edit.text().strip()
        tsk = TheSleuthKitIntegration(bin_dir=d if d else None)
        status = tsk.get_status()
        if status["is_available"]:
            tools_found = [k for k, v in status["tools"].items() if v]
            QMessageBox.information(
                self,
                "The Sleuth Kit Detected",
                f"The Sleuth Kit is valid!\n\nVersion: {status.get('version')}\nTools Found: {', '.join(tools_found)}"
            )
        else:
            QMessageBox.warning(
                self,
                "The Sleuth Kit Not Found",
                f"The Sleuth Kit is not available:\n{status.get('installation_notice')}"
            )

    def _save_settings(self):
        pr_path = self.pr_path_edit.text().strip()
        tsk_dir = self.tsk_path_edit.text().strip()
        dry_run = self.chk_dry_run_default.isChecked()

        settings_to_save = {
            "photorec_path": pr_path,
            "tsk_bin_dir": tsk_dir,
            "dry_run_default": dry_run,
        }

        success = save_user_settings(settings_to_save)
        if success:
            config.PHOTOREC_PATH = pr_path
            config.TSK_BIN_DIR = tsk_dir
            config.DRY_RUN = dry_run
            self.pr_integration = PhotoRecIntegration(binary_path=pr_path if pr_path else None)
            self.tsk_integration = TheSleuthKitIntegration(bin_dir=tsk_dir if tsk_dir else None)
            QMessageBox.information(
                self,
                "Settings Saved",
                "Configuration settings applied and persisted successfully."
            )
        else:
            QMessageBox.critical(
                self,
                "Save Failed",
                "Failed to write configuration file to disk."
            )
