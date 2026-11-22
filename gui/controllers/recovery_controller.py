"""
Recovery Controller and Background Workers for RecoverX GUI
Executes asynchronous scanning, carving, and recovery without blocking the UI thread.
Provides real-time file-by-file progress, cancelability, and forensic report generation.
"""
from PySide6.QtCore import QThread, Signal
from pathlib import Path
from typing import List, Dict, Any, Optional

from engine.orchestrator import RecoveryOrchestrator
from engine.signature_scanner import SignatureScanner, CarvedItem
from engine.recovery_manager import RecoveryManager
from engine.report_generator import ReportGenerator
from engine.history_manager import HistoryManager
from integrations.sleuthkit.runner import TheSleuthKitIntegration
from integrations.photorec.runner import PhotoRecIntegration
from utils.logging_config import logger

class ScanWorker(QThread):
    progress_updated = Signal(int, int, int)  # current_bytes, total_bytes, percent
    item_discovered = Signal(dict)           # Carved/discovered file dictionary
    scan_finished = Signal(dict)             # Summary statistics
    scan_error = Signal(str)                 # Error message

    def __init__(
        self,
        source_path: Path,
        scan_mode: str = "deep_carving",
        target_formats: Optional[List[str]] = None,
        use_photorec: bool = False,
        use_tsk: bool = False,
        parent=None
    ):
        super().__init__(parent)
        self.source_path = Path(source_path)
        self.scan_mode = scan_mode
        self.target_formats = target_formats
        self.use_photorec = use_photorec
        self.use_tsk = use_tsk
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        try:
            from engine.win32_raw_reader import Win32RawDeviceReader, is_raw_device_path

            is_raw = is_raw_device_path(self.source_path)
            if not is_raw and not self.source_path.exists():
                self.scan_error.emit(f"Source path does not exist: {self.source_path}")
                return

            # Determine real device/image size accurately
            file_size = 0
            try:
                reader = Win32RawDeviceReader(self.source_path)
                file_size = reader.get_size()
            except PermissionError as pe:
                self.scan_error.emit(str(pe))
                return
            except Exception:
                if not is_raw and self.source_path.is_file():
                    file_size = self.source_path.stat().st_size

            discovered_items = []
            bytes_scanned = [0]

            orchestrator = RecoveryOrchestrator(
                use_native_carver=True,
                use_photorec=self.use_photorec,
                use_tsk=self.use_tsk
            )

            def on_progress(current, total):
                if not self._is_cancelled:
                    bytes_scanned[0] = current
                    if total > 0:
                        pct = int((current / total) * 100)
                        self.progress_updated.emit(current, total, pct)

            def on_item(item_dict: dict):
                if not self._is_cancelled:
                    discovered_items.append(item_dict)
                    self.item_discovered.emit(item_dict)

            orchestrator.scan(
                self.source_path,
                progress_callback=on_progress,
                item_callback=on_item,
                is_cancelled=lambda: self._is_cancelled
            )

            actual_bytes = bytes_scanned[0]
            if actual_bytes == 0 and file_size > 0 and len(discovered_items) == 0:
                self.scan_error.emit(
                    f"Forensic Scan Failure: 0 bytes processed from '{self.source_path}'.\n\n"
                    "Direct physical or volume access on Windows requires Administrator privileges. "
                    "Please restart RecoverX as Administrator, or verify the drive is mounted and readable."
                )
                return

            valid_count = sum(1 for i in discovered_items if i.get("is_valid", False))
            dup_count = sum(1 for i in discovered_items if i.get("is_duplicate", False))

            summary = {
                "source_path": str(self.source_path),
                "file_size": file_size,
                "bytes_scanned": actual_bytes if actual_bytes > 0 else file_size,
                "total_items": len(discovered_items),
                "valid_items": valid_count,
                "duplicate_items": dup_count,
                "items": discovered_items
            }
            self.scan_finished.emit(summary)

        except PermissionError as pe:
            logger.error(f"Permission denied during scan worker execution: {pe}")
            self.scan_error.emit(str(pe))
        except Exception as e:
            logger.error(f"Error during scan worker execution: {e}")
            self.scan_error.emit(str(e))

class ExtractionWorker(QThread):
    progress_updated = Signal(int, int, str, dict)  # current_file, total_files, current_name, counts
    file_recovered = Signal(dict)                  # single recovered file info
    extraction_finished = Signal(dict)             # final report dict
    extraction_error = Signal(str)

    def __init__(
        self,
        items: List[Dict[str, Any]],
        source_path: Path,
        destination_dir: Path,
        skip_duplicates: bool = True,
        parent=None
    ):
        super().__init__(parent)
        self.items = items
        self.source_path = Path(source_path)
        self.destination_dir = Path(destination_dir)
        self.skip_duplicates = skip_duplicates
        self._is_cancelled = False

    def cancel(self):
        """Signals the extraction loop to stop cleanly."""
        self._is_cancelled = True

    def run(self):
        try:
            rec_mgr = RecoveryManager(output_dir=self.destination_dir)

            def on_progress(current: int, total: int, current_filename: str, counts: dict):
                self.progress_updated.emit(current, total, current_filename, counts)

            def is_cancelled() -> bool:
                return self._is_cancelled

            recovery_res = rec_mgr.recover_artifacts(
                artifacts=self.items,
                source_path=self.source_path,
                skip_duplicates=self.skip_duplicates,
                progress_callback=on_progress,
                is_cancelled_callback=is_cancelled
            )

            # Generate final markdown and json forensic report
            rep_gen = ReportGenerator()
            report_data = {
                "source_path": str(self.source_path),
                "recovery_results": recovery_res
            }
            paths = rep_gen.generate_report(report_data, title="Desktop_GUI_Recovery_Session")
            recovery_res["markdown_report"] = paths["markdown_report"]
            recovery_res["json_report"] = paths["json_report"]

            # Record into persistent SQLite history
            try:
                hist_mgr = HistoryManager()
                recovered_files_list = recovery_res.get("recovered_files", [])
                inv_id = hist_mgr.record_investigation(
                    source_name=self.source_path.name,
                    source_path=str(self.source_path),
                    source_type="disk_image" if self.source_path.suffix.lower() in (".img", ".raw", ".dd") else "storage_media",
                    scan_mode="Forensic Deep Signature Carving",
                    engines_used="RecoverX Native Carver",
                    files_discovered=len(self.items),
                    files_recovered=recovery_res.get("total_recovered", 0),
                    files_validated=recovery_res.get("verified_success", 0),
                    total_bytes=sum(f.get("size", 0) for f in recovered_files_list),
                    status="Completed" if not self._is_cancelled else "Cancelled",
                    output_dir=str(self.destination_dir),
                    report_path=str(paths.get("markdown_report", ""))
                )
                if recovered_files_list:
                    hist_mgr.record_investigation_files(inv_id, recovered_files_list)
            except Exception as hist_err:
                logger.warning(f"Could not persist investigation history: {hist_err}")

            self.extraction_finished.emit(recovery_res)

        except Exception as e:
            logger.error(f"Error during extraction worker execution: {e}")
            self.extraction_error.emit(str(e))
