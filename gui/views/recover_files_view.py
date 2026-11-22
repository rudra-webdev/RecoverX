"""
Recover Files View for RecoverX GUI (Premium Light Redesign)
Complete interactive file recovery workflow:
Source Selection -> Explicit Approval -> Progressive Scanning -> Filtering & Preview -> Selective Extraction.
Features dynamic selection counts, real-time worker progress, destination safety validation,
and completion reporting with folder access.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QFileDialog, QTableView, QProgressBar, QMessageBox,
    QHeaderView, QSplitter, QCheckBox, QAbstractItemView, QDialog,
    QTextEdit
)
from PySide6.QtCore import Qt, QModelIndex, QUrl
from PySide6.QtGui import QDesktopServices
from pathlib import Path
from typing import Optional, List
import os

from engine.drive_manager import DriveManager, StorageSource
from gui.models.file_table_model import FileTableModel
from gui.widgets.filter_bar import FilterBar
from gui.widgets.preview_panel import PreviewPanel
from gui.controllers.recovery_controller import ScanWorker, ExtractionWorker
from config import RECOVERED_DIR, REPORTS_DIR
from utils.logging_config import logger

class RecoveryCompleteDialog(QDialog):
    """Forensic recovery summary dialog with one-click folder and report opening (Light Theme)."""
    def __init__(self, summary: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Forensic Recovery Complete — RecoverX")
        self.resize(540, 380)
        self.summary = summary
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)

        header = QLabel("✅ File Extraction & Verification Complete")
        header.setStyleSheet("font-size: 16px; font-weight: 700; color: #059669;")
        layout.addWidget(header)

        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setStyleSheet("""
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 10px;
            color: #1e293b;
        """)

        out_dir = self.summary.get("output_directory", "")
        rep_md = self.summary.get("markdown_report", "")

        lines = [
            f"Total Selected Files  : {self.summary.get('total_selected', 0)}",
            f"Successfully Verified : {self.summary.get('verified_success', self.summary.get('total_recovered', 0))}",
            f"Partially Recovered   : {self.summary.get('partial_success', 0)}",
            f"Skipped (Duplicates)  : {self.summary.get('skipped_duplicates', 0)}",
            f"Metadata Records Only : {self.summary.get('metadata_only_count', 0)}",
            f"Failed Extractions    : {self.summary.get('failed_count', 0)}",
            "",
            f"Destination Directory : {out_dir}",
            f"Forensic Report       : {rep_md}",
            "",
            "Forensic Note: All extracted artifacts have been hashed with SHA-256 and verified.",
            "Files are organized by format in isolated destination folders."
        ]
        info_text.setPlainText("\n".join(lines))
        layout.addWidget(info_text)

        btn_layout = QHBoxLayout()
        btn_open_folder = QPushButton("📂 Open Recovery Folder")
        btn_open_folder.setObjectName("primaryButton")
        btn_open_folder.clicked.connect(self._open_folder)

        btn_view_report = QPushButton("📄 View Forensic Report")
        btn_view_report.clicked.connect(self._view_report)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)

        btn_layout.addWidget(btn_open_folder)
        btn_layout.addWidget(btn_view_report)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

    def _open_folder(self):
        out_dir = self.summary.get("output_directory")
        if out_dir and Path(out_dir).is_dir():
            QDesktopServices.openUrl(QUrl.fromLocalFile(out_dir))

    def _view_report(self):
        rep = self.summary.get("markdown_report")
        if rep and Path(rep).is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(rep))

class RecoverFilesView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.sources: List[StorageSource] = []
        self.scan_worker: Optional[ScanWorker] = None
        self.extraction_worker: Optional[ExtractionWorker] = None
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

        search_icon = QLabel("⌕")
        search_icon.setStyleSheet("font-size: 22px; color: #4f46e5; font-weight: bold;")
        title = QLabel("Recover Files")
        title.setObjectName("headingLabel")
        title_row.addWidget(search_icon)
        title_row.addWidget(title)
        title_row.addStretch()

        desc = QLabel("Forensic signature carving and filesystem metadata recovery across images and storage volumes")
        desc.setObjectName("subheadingLabel")

        title_box.addLayout(title_row)
        title_box.addWidget(desc)
        layout.addLayout(title_box)

        # 1. Source & Engine Configuration Card
        source_frame = QFrame()
        source_frame.setObjectName("cardFrame")
        source_layout = QHBoxLayout(source_frame)
        source_layout.setContentsMargins(18, 14, 18, 14)
        source_layout.setSpacing(14)

        # Source Combo
        src_box = QVBoxLayout()
        src_lbl = QLabel("SOURCE STORAGE / IMAGE:")
        src_lbl.setObjectName("statTitleLabel")
        self.source_combo = QComboBox()
        self.source_combo.setMinimumWidth(280)
        src_box.addWidget(src_lbl)
        src_box.addWidget(self.source_combo)
        source_layout.addLayout(src_box)

        # Browse Image Button
        self.btn_browse_img = QPushButton("📁 Browse Image (.img/.raw/.dd)")
        self.btn_browse_img.clicked.connect(self._on_browse_image)
        source_layout.addWidget(self.btn_browse_img, alignment=Qt.AlignmentFlag.AlignBottom)

        # Scan Mode
        mode_box = QVBoxLayout()
        mode_lbl = QLabel("SCAN MODE:")
        mode_lbl.setObjectName("statTitleLabel")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "Deep Signature Carving (RecoverX Carver)",
            "Filesystem Metadata Scan (TSK / NTFS / FAT)",
            "Composite Scan (Metadata + Deep Carving)"
        ])
        mode_box.addWidget(mode_lbl)
        mode_box.addWidget(self.mode_combo)
        source_layout.addLayout(mode_box)

        source_layout.addStretch()

        # Start Scan Button
        self.btn_start_scan = QPushButton("▶ Start Forensic Scan")
        self.btn_start_scan.setObjectName("primaryButton")
        self.btn_start_scan.clicked.connect(self._start_scan_flow)
        source_layout.addWidget(self.btn_start_scan, alignment=Qt.AlignmentFlag.AlignBottom)

        layout.addWidget(source_frame)

        # 2. Scan Progress Bar & Live Status
        self.progress_frame = QFrame()
        self.progress_frame.setObjectName("cardFrame")
        prog_layout = QVBoxLayout(self.progress_frame)
        prog_layout.setContentsMargins(16, 12, 16, 12)
        prog_layout.setSpacing(6)

        prog_header = QHBoxLayout()
        self.lbl_scan_status = QLabel("Ready to scan. Select source media and click Start.")
        self.lbl_scan_status.setStyleSheet("font-weight: 600; color: #0f172a;")
        self.lbl_scan_stats = QLabel("0 files discovered | 0 B processed")
        self.lbl_scan_stats.setStyleSheet("color: #64748b; font-size: 12px;")

        self.btn_cancel = QPushButton("⛔ Cancel")
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(self._on_cancel_clicked)

        prog_header.addWidget(self.lbl_scan_status)
        prog_header.addStretch()
        prog_header.addWidget(self.lbl_scan_stats)
        prog_header.addWidget(self.btn_cancel)
        prog_layout.addLayout(prog_header)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        prog_layout.addWidget(self.progress_bar)

        layout.addWidget(self.progress_frame)

        # 3. Filter Bar
        self.filter_bar = FilterBar()
        self.filter_bar.category_changed.connect(lambda c: self.model.set_filter(category=c))
        self.filter_bar.status_changed.connect(lambda s: self.model.set_filter(status=s))
        self.filter_bar.search_changed.connect(lambda q: self.model.set_filter(search=q))
        self.filter_bar.select_all_clicked.connect(lambda sel: self.model.select_all(sel))
        layout.addWidget(self.filter_bar)

        # 4. Results Splitter: Table View + Preview Inspector
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Table View
        self.table_view = QTableView()
        self.model = FileTableModel(self)
        self.table_view.setModel(self.model)
        self.table_view.setSortingEnabled(True)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table_view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table_view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.setColumnWidth(0, 36)
        self.table_view.setColumnWidth(1, 180)
        self.table_view.setColumnWidth(2, 60)
        self.table_view.setColumnWidth(3, 90)
        self.table_view.setColumnWidth(4, 180)
        self.table_view.setColumnWidth(5, 80)
        self.table_view.setColumnWidth(6, 120)
        self.table_view.setColumnWidth(7, 80)
        self.table_view.setColumnWidth(8, 110)

        self.table_view.clicked.connect(self._on_table_row_clicked)
        self.model.selection_changed.connect(self._on_selection_changed)

        splitter.addWidget(self.table_view)

        # Preview Inspector Panel
        self.preview_panel = PreviewPanel(self)
        splitter.addWidget(self.preview_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter, 1)

        # 5. Bottom Action Bar: Selection count, Duplicate toggle, and Recover Selected Button
        action_bar = QHBoxLayout()
        action_bar.setSpacing(12)

        self.lbl_selected_count = QLabel("0 files selected for recovery")
        self.lbl_selected_count.setStyleSheet("font-weight: 700; color: #4f46e5; font-size: 13px;")
        action_bar.addWidget(self.lbl_selected_count)

        self.chk_skip_dupes = QCheckBox("Skip duplicates (SHA-256 matching)")
        self.chk_skip_dupes.setChecked(True)
        action_bar.addWidget(self.chk_skip_dupes)

        action_bar.addStretch()

        # Dedicated "Recover Selected (N)" button in primary Indigo
        self.btn_recover_selected = QPushButton("💾 Recover Selected Files (0)")
        self.btn_recover_selected.setObjectName("primaryButton")
        self.btn_recover_selected.setEnabled(False)
        self.btn_recover_selected.clicked.connect(self._start_recovery_flow)
        action_bar.addWidget(self.btn_recover_selected)

        layout.addLayout(action_bar)

        self._populate_sources()

    def _on_selection_changed(self, count: int):
        """Immediately updates recovery button state and count when selections change."""
        self.lbl_selected_count.setText(f"{count} files selected for recovery")
        self.btn_recover_selected.setText(f"💾 Recover Selected Files ({count})")
        self.btn_recover_selected.setEnabled(count > 0)

    def _populate_sources(self):
        """Populates source dropdown with detected logical drives and images."""
        self.source_combo.clear()
        self.sources.clear()

        # Check for local sample.img or existing images
        if Path("sample.img").is_file():
            try:
                img_src = DriveManager.inspect_disk_image(Path("sample.img"))
                self.sources.append(img_src)
                self.source_combo.addItem(f"📁 {img_src.name} ({img_src.total_bytes} bytes)", img_src)
            except Exception:
                pass

        try:
            drives = DriveManager.list_logical_drives()
            for d in drives:
                self.sources.append(d)
                sys_tag = " ⚠️ SYSTEM DRIVE" if d.is_system_drive else ""
                icon = "💾" if d.source_type == "removable_usb" else "💿"
                self.source_combo.addItem(f"{icon} {d.name} [{d.filesystem}, {d.total_gb:.1f} GB]{sys_tag}", d)
        except Exception as e:
            logger.warning(f"Failed to list logical drives: {e}")

    def _on_browse_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image for Read-Only Carving",
            "",
            "Forensic Images (*.img *.raw *.dd *.iso);;All Files (*.*)"
        )
        if file_path:
            try:
                src = DriveManager.inspect_disk_image(Path(file_path))
                self.sources.insert(0, src)
                self.source_combo.insertItem(0, f"📁 {src.name} ({src.total_bytes} bytes)", src)
                self.source_combo.setCurrentIndex(0)
            except Exception as e:
                QMessageBox.critical(self, "Invalid Image", f"Could not open disk image: {e}")

    def _on_table_row_clicked(self, index: QModelIndex):
        item = self.model.get_item(index.row())
        if item:
            self.preview_panel.display_file(item)

    def _on_cancel_clicked(self):
        """Cancels running scan or extraction worker."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.lbl_scan_status.setText("Cancelling forensic scan...")
        if self.extraction_worker and self.extraction_worker.isRunning():
            self.extraction_worker.cancel()
            self.lbl_scan_status.setText("Cancelling file recovery...")

    def _start_scan_flow(self):
        idx = self.source_combo.currentIndex()
        if idx < 0 or idx >= len(self.sources):
            QMessageBox.warning(self, "No Source Selected", "Please select a target storage device or disk image.")
            return

        source = self.sources[idx]

        # Safety Check: Never scan system drive without explicit confirmation
        if source.is_system_drive:
            resp = QMessageBox.warning(
                self,
                "System Drive Warning",
                f"Drive {source.identifier} is your active Windows system drive.\n\n"
                "Scanning an active operating system drive can yield high noise and incomplete results.\n"
                "Are you sure you want to proceed in read-only mode?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if resp != QMessageBox.StandardButton.Yes:
                return

        # Explicit Permission Confirmation
        confirm = QMessageBox.question(
            self,
            "Approve Read-Only Forensic Scan",
            f"Target: {source.name}\n"
            f"Path: {source.identifier}\n"
            f"Safety: STRICT READ-ONLY\n\n"
            "RecoverX will scan the media without modifying any source sectors.\n"
            "Do you approve starting the scan?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        # Prepare UI
        self.model.clear()
        self.preview_panel.clear_preview()
        self.progress_bar.setValue(0)
        self.lbl_scan_status.setText(f"Scanning {source.name} (Read-Only)...")
        self.btn_start_scan.setEnabled(False)
        self.btn_cancel.setVisible(True)

        # Mode configuration
        mode_text = self.mode_combo.currentText()
        use_tsk = "Metadata" in mode_text or "Composite" in mode_text

        # Start Worker Thread
        self.scan_worker = ScanWorker(
            source_path=Path(source.identifier),
            scan_mode=mode_text,
            use_tsk=use_tsk,
            parent=self
        )
        self.scan_worker.progress_updated.connect(self._on_scan_progress)
        self.scan_worker.item_discovered.connect(self._on_item_discovered)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.scan_error.connect(self._on_scan_error)
        self.scan_worker.start()

    def _on_scan_progress(self, current: int, total: int, pct: int):
        self.progress_bar.setValue(pct)
        cur_mb = current / (1024 * 1024)
        tot_mb = total / (1024 * 1024)
        self.lbl_scan_stats.setText(f"{len(self.model._all_items)} files discovered | {cur_mb:.1f} MB / {tot_mb:.1f} MB")

    def _on_item_discovered(self, item_dict: dict):
        self.model.add_item(item_dict)
        self.lbl_scan_stats.setText(f"{len(self.model._all_items)} files discovered")

    def _on_scan_finished(self, summary: dict):
        self.progress_bar.setValue(100)
        self.lbl_scan_status.setText("Scan Complete. Ready to filter and extract.")
        self.btn_start_scan.setEnabled(True)
        self.btn_cancel.setVisible(False)
        QMessageBox.information(
            self,
            "Scan Complete",
            f"Forensic scan finished successfully!\n\n"
            f"Total Artifacts Discovered: {summary['total_items']}\n"
            f"Valid Files: {summary['valid_items']}\n"
            f"Duplicates Identified: {summary['duplicate_items']}\n\n"
            "Select items using the checkboxes and click 'Recover Selected Files'."
        )

    def _on_scan_error(self, err: str):
        self.btn_start_scan.setEnabled(True)
        self.btn_cancel.setVisible(False)
        self.lbl_scan_status.setText(f"Scan Error: {err}")
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scanning:\n{err}")

    def _start_recovery_flow(self):
        selected_entries = self.model.get_selected_items()
        if not selected_entries:
            QMessageBox.warning(self, "No Files Selected", "Please select at least one file to recover using the checkboxes.")
            return

        # 1. Directory-selection dialog
        dest_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Destination Directory (Must NOT be source device)",
            str(RECOVERED_DIR)
        )
        if not dest_dir:
            return

        dest_path = Path(dest_dir).resolve()
        idx = self.source_combo.currentIndex()
        source_path = Path(self.sources[idx].identifier).resolve()

        # 2. Mandatory Safety Validation: Destination cannot overlap or be source device
        if dest_path == source_path or dest_path in source_path.parents or source_path in dest_path.parents:
            QMessageBox.critical(
                self,
                "Forensic Safety Violation",
                "Destination directory CANNOT be identical to, contain, or be located inside the source media.\n\n"
                "Please choose an isolated folder on a different storage drive."
            )
            return

        # 3. Final Confirmation Dialog
        confirm = QMessageBox.question(
            self,
            "Confirm File Recovery",
            f"Recovering {len(selected_entries)} selected artifacts to:\n{dest_path}\n\n"
            f"Source Media     : {source_path}\n"
            f"Skip Duplicates  : {'Yes (SHA-256 match)' if self.chk_skip_dupes.isChecked() else 'No'}\n\n"
            "Proceed with extraction?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        items_raw = [e.raw for e in selected_entries]
        self.btn_recover_selected.setEnabled(False)
        self.btn_cancel.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_scan_status.setText(f"Recovering {len(items_raw)} files to {dest_path.name}...")

        # 4. Start Background Extraction Worker
        self.extraction_worker = ExtractionWorker(
            items=items_raw,
            source_path=source_path,
            destination_dir=dest_path,
            skip_duplicates=self.chk_skip_dupes.isChecked(),
            parent=self
        )
        self.extraction_worker.progress_updated.connect(self._on_extraction_progress)
        self.extraction_worker.extraction_finished.connect(self._on_extraction_finished)
        self.extraction_worker.extraction_error.connect(self._on_extraction_error)
        self.extraction_worker.start()

    def _on_extraction_progress(self, current: int, total: int, filename: str, counts: dict):
        """Updates UI with file-by-file extraction progress and stats."""
        pct = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.lbl_scan_status.setText(f"Extracting ({current}/{total}): {filename}")
        self.lbl_scan_stats.setText(
            f"Verified: {counts.get('success', 0)} | Partial: {counts.get('partial', 0)} | "
            f"Skipped: {counts.get('skipped', 0)} | Failed: {counts.get('failed', 0)}"
        )

    def _on_extraction_finished(self, results: dict):
        self.btn_cancel.setVisible(False)
        self.progress_bar.setValue(100)
        selected_count = len(self.model.get_selected_items())
        self.btn_recover_selected.setEnabled(selected_count > 0)
        self.lbl_scan_status.setText(f"Recovery complete. {results['total_recovered']} files written.")

        # Show comprehensive forensic completion dialog
        dlg = RecoveryCompleteDialog(results, self)
        dlg.exec()

        # Refresh dashboard and history views if accessible
        try:
            main_win = self.window()
            if hasattr(main_win, "view_dashboard") and hasattr(main_win.view_dashboard, "refresh_data"):
                main_win.view_dashboard.refresh_data()
            if hasattr(main_win, "view_history") and hasattr(main_win.view_history, "refresh_reports"):
                main_win.view_history.refresh_reports()
            if hasattr(main_win, "view_reports") and hasattr(main_win.view_reports, "refresh_data"):
                main_win.view_reports.refresh_data()
        except Exception as e:
            logger.warning(f"Could not refresh views after extraction: {e}")

    def _on_extraction_error(self, err: str):
        self.btn_cancel.setVisible(False)
        selected_count = len(self.model.get_selected_items())
        self.btn_recover_selected.setEnabled(selected_count > 0)
        self.lbl_scan_status.setText(f"Recovery Error: {err}")
        QMessageBox.critical(self, "Recovery Error", f"Extraction failed:\n{err}")
