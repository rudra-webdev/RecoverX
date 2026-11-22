"""
Comprehensive Automated Test Suite for GUI, Integrations (PhotoRec, TSK),
Drive Discovery, File Preview, Filtering, and Safety Constraints.
"""
import pytest
import os
import io
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure Qt runs offscreen in headless test runners
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from gui.app import RecoverXMainWindow
from gui.models.file_table_model import FileTableModel, FileItemEntry
from gui.widgets.preview_panel import PreviewPanel
from engine.drive_manager import DriveManager, StorageSource
from engine.recovery_manager import RecoveryManager
from engine.file_validator import FileValidator
from engine.signature_scanner import SignatureScanner, CarvedItem
from integrations.photorec.runner import PhotoRecIntegration
from integrations.sleuthkit.runner import TheSleuthKitIntegration
from utils.network_guard import enable_offline_mode, is_offline_mode_active
from utils.hashing import compute_sha256
from tests.test_signatures import (
    create_synthetic_png,
    create_synthetic_jpg,
    create_synthetic_mp4,
    create_synthetic_avi,
    create_synthetic_zip,
    create_synthetic_pdf
)

@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app

def test_gui_startup_and_views(qapp):
    """Verifies that the main desktop window initializes with all 7 views and navigates cleanly."""
    window = RecoverXMainWindow()
    assert window is not None
    assert window.windowTitle() == "RecoverX — Forensic Data Recovery Engine"
    assert window.stacked_views.count() == 7

    # Test navigation through all 7 views
    for view_idx in range(7):
        window.sidebar.navigation_changed.emit(view_idx)
        assert window.stacked_views.currentIndex() == view_idx

    window.close()

def test_drive_discovery():
    """Verifies logical drive discovery and attributes."""
    drives = DriveManager.list_logical_drives()
    assert isinstance(drives, list)
    assert len(drives) > 0

    first_drive = drives[0]
    assert isinstance(first_drive, StorageSource)
    assert first_drive.total_bytes > 0
    assert first_drive.total_gb >= 0.0
    assert first_drive.is_read_only is True

def test_recovery_result_rendering_and_filtering(qapp):
    """Tests FileTableModel data population, checkbox selection, and category/status filtering."""
    model = FileTableModel()

    sample_items = [
        {"filename": "photo1.jpg", "extension": "jpg", "category": "Images", "length": 50000, "is_valid": True, "confidence": 1.0, "sha256": "a" * 64},
        {"filename": "video1.mp4", "extension": "mp4", "category": "Videos", "length": 1500000, "is_valid": True, "confidence": 0.9, "sha256": "b" * 64},
        {"filename": "doc1.pdf", "extension": "pdf", "category": "Documents", "length": 80000, "is_valid": True, "confidence": 0.95, "sha256": "c" * 64},
        {"filename": "corrupt.png", "extension": "png", "category": "Images", "length": 200, "is_valid": False, "confidence": 0.2, "sha256": "d" * 64},
        {"filename": "frag.zip", "extension": "zip", "category": "Archives", "length": 4000, "is_valid": True, "confidence": 0.6, "fragmented_warning": True, "sha256": "e" * 64}
    ]

    model.set_items(sample_items)
    assert model.rowCount() == 5
    assert model.columnCount() == 10

    # Test Checkbox Selection
    index_cb = model.index(0, 0)
    assert model.data(index_cb, Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Unchecked
    model.setData(index_cb, Qt.CheckState.Checked.value, Qt.ItemDataRole.CheckStateRole)
    assert model.data(index_cb, Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Checked
    assert len(model.get_selected_items()) == 1

    # Test Select All / Deselect All
    model.select_all(True)
    assert len(model.get_selected_items()) == 5
    model.select_all(False)
    assert len(model.get_selected_items()) == 0

    # Test Category Filtering
    model.set_filter(category="Images")
    assert model.rowCount() == 2

    model.set_filter(category="Documents")
    assert model.rowCount() == 1

    model.set_filter(category="All")
    assert model.rowCount() == 5

    # Test Status Filtering
    model.set_filter(status="Recoverable")
    # photo1, video1, doc1
    assert model.rowCount() == 3

    model.set_filter(status="Partially recoverable")
    # frag.zip
    assert model.rowCount() == 1

    model.set_filter(status="Invalid or incomplete")
    # corrupt.png
    assert model.rowCount() == 1

    model.set_filter(status="All")
    assert model.rowCount() == 5

def test_image_preview_panel(qapp):
    """Tests PreviewPanel with synthetic valid image and text inspector."""
    panel = PreviewPanel()
    png_data = create_synthetic_png()

    raw_item = {
        "filename": "test_preview.png",
        "extension": "png",
        "category": "Images",
        "length": len(png_data),
        "data": png_data,
        "is_valid": True,
        "confidence": 1.0,
        "offset": 4096,
        "sha256": compute_sha256(png_data),
        "details": {"dimensions": "2x2"}
    }

    entry = FileItemEntry(raw_item)
    panel.display_file(entry)

    assert "test_preview.png" in panel.meta_text.toPlainText()
    assert "2x2" in panel.meta_text.toPlainText()
    assert "Forensic Disclaimer" in panel.disclaimer_label.text()

def test_video_metadata_validation():
    """Tests structural validation on synthetic MP4 and AVI files."""
    mp4_bytes = create_synthetic_mp4()
    val_mp4 = FileValidator.validate(mp4_bytes, "mp4")
    assert val_mp4["is_valid"] is True
    assert val_mp4["category"] == "Videos"
    assert val_mp4["details"]["has_media_atoms"] is True

    avi_bytes = create_synthetic_avi()
    val_avi = FileValidator.validate(avi_bytes, "avi")
    assert val_avi["is_valid"] is True
    assert val_avi["category"] == "Videos"

def test_photorec_integration_mocked(tmp_path: Path):
    """Tests PhotoRecIntegration using mocked subprocess and output directory parsing."""
    dummy_bin = tmp_path / "photorec_win.exe"
    dummy_bin.write_bytes(b"dummy")
    photorec = PhotoRecIntegration(binary_path=str(dummy_bin))

    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(
            args=[str(dummy_bin), "/version"],
            returncode=0,
            stdout="PhotoRec 7.2, Data Recovery Utility, Oct 2019\nChristophe GRENIER <grenier@cgsecurity.org>\nhttps://www.cgsecurity.org"
        )
        status = photorec.get_status()
        assert status["is_available"] is True
        assert "7.2" in status["version"]
        assert status["license_info"]["author"] == "Christophe GRENIER / CGSecurity"

    # Simulate PhotoRec output carving directory structure
    session_dir = tmp_path / "photorec_session"
    recup_dir = session_dir / "recup_dir.1"
    recup_dir.mkdir(parents=True)

    png_data = create_synthetic_png()
    (recup_dir / "f0000001.png").write_bytes(png_data)
    (recup_dir / "f0000002.txt").write_text("Recovered Text Payload", encoding="utf-8")

    parsed = photorec.parse_recovered_output(session_dir)
    assert len(parsed) == 2
    png_entry = next(p for p in parsed if p["filename"] == "f0000001.png")
    assert png_entry["extension"] == "png"
    assert png_entry["is_valid"] is True
    assert png_entry["sha256"] == compute_sha256(png_data)

def test_sleuthkit_integration_mocked(tmp_path: Path):
    """Tests TheSleuthKitIntegration using mocked fls, fsstat, and icat output."""
    tsk = TheSleuthKitIntegration()
    dummy_fls = tmp_path / "fls.exe"
    dummy_fls.write_bytes(b"dummy")
    # Mock tool paths with existing dummy files
    tsk.tool_paths = {
        "fls": str(dummy_fls),
        "fsstat": str(dummy_fls),
        "icat": str(dummy_fls),
        "mmls": str(dummy_fls)
    }

    # 1. Test version detection
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(
            args=[str(dummy_fls), "-V"],
            returncode=0,
            stdout="The Sleuth Kit ver 4.12.0\n"
        )
        st = tsk.get_status()
        assert st["is_available"] is True
        assert "4.12.0" in st["version"]

    # 2. Test deleted entry identification via fls output
    fls_mock_output = (
        "d/d * 144-144-1: /Documents/DeletedReports\n"
        "r/r * 1530-144-4: /Pictures/LostPhoto.jpg\n"
        "r/r 1600-144-1: /System/active.dll\n"
    )
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(
            args=[str(dummy_fls), "-r", "-p", "-d", "test.img"],
            returncode=0,
            stdout=fls_mock_output
        )
        entries = tsk.find_deleted_entries(Path("test.img"))
        assert len(entries) == 3
        # Inode 1530-144-4
        jpg_entry = next(e for e in entries if e["filename"] == "LostPhoto.jpg")
        assert jpg_entry["is_deleted_record"] is True
        assert jpg_entry["status"] == "METADATA_RECORD_IDENTIFIED"
        assert jpg_entry["content_extracted"] is False

def test_recovery_destination_safety(tmp_path: Path):
    """Tests that RecoveryManager rejects extraction when destination is source or inside source."""
    source_img = tmp_path / "disk.img"
    source_img.write_bytes(b"\x00" * 1024)

    # Destination identical to source
    rec_mgr = RecoveryManager(output_dir=tmp_path)
    with pytest.raises(PermissionError) as exc_info:
        rec_mgr.recover_carved_items([], source_path=tmp_path)
    assert "Forensic Safety Violation" in str(exc_info.value)

def test_duplicate_filenames_and_invalid_handling(tmp_path: Path):
    """Tests unique file naming and corrupt file handling during carving and recovery."""
    out_dir = tmp_path / "recovered_unique"
    rec_mgr = RecoveryManager(output_dir=out_dir)

    png_data = create_synthetic_png()
    png_hash = compute_sha256(png_data)

    item1 = CarvedItem(
        offset=0,
        length=len(png_data),
        extension="png",
        data=png_data,
        sha256=png_hash,
        is_valid=True,
        confidence=1.0,
        details={}
    )

    dummy_source = tmp_path / "source.img"
    dummy_source.write_bytes(b"\x00" * 512)

    res = rec_mgr.recover_carved_items([item1], source_path=dummy_source)
    assert res["total_recovered"] == 1
    recovered_file = Path(res["files"][0]["path"])
    assert recovered_file.exists()
    assert compute_sha256(recovered_file) == png_hash

def test_offline_mode_enforcement():
    """Confirms offline isolation guard blocks outbound socket connections."""
    enable_offline_mode()
    assert is_offline_mode_active() is True

    import socket
    with pytest.raises(PermissionError) as exc:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("1.1.1.1", 80))
    assert "Offline Security Guard" in str(exc.value)

def test_recover_selected_button_state(qapp):
    """Verifies that Recover Selected Files (N) button dynamically updates based on table checkbox selections."""
    from gui.views.recover_files_view import RecoverFilesView
    view = RecoverFilesView()

    # Initial state: 0 selected, disabled
    assert "Recover Selected Files (0)" in view.btn_recover_selected.text()
    assert view.btn_recover_selected.isEnabled() is False

    # Populate items
    sample_items = [
        {"filename": "item1.png", "extension": "png", "category": "Images", "length": 500, "is_valid": True, "sha256": "1" * 64},
        {"filename": "item2.jpg", "extension": "jpg", "category": "Images", "length": 1500, "is_valid": True, "sha256": "2" * 64},
    ]
    view.model.set_items(sample_items)
    assert view.btn_recover_selected.isEnabled() is False

    # Check item 0
    idx0 = view.model.index(0, 0)
    view.model.setData(idx0, Qt.CheckState.Checked.value, Qt.ItemDataRole.CheckStateRole)
    assert "Recover Selected Files (1)" in view.btn_recover_selected.text()
    assert view.btn_recover_selected.isEnabled() is True

    # Check item 1
    idx1 = view.model.index(1, 0)
    view.model.setData(idx1, Qt.CheckState.Checked.value, Qt.ItemDataRole.CheckStateRole)
    assert "Recover Selected Files (2)" in view.btn_recover_selected.text()
    assert view.btn_recover_selected.isEnabled() is True

    # Deselect all
    view.model.select_all(False)
    assert "Recover Selected Files (0)" in view.btn_recover_selected.text()
    assert view.btn_recover_selected.isEnabled() is False

    view.close()

def test_table_model_sorting(qapp):
    """Verifies column sorting by size, filename, and offset."""
    model = FileTableModel()
    items = [
        {"filename": "b_file.png", "extension": "png", "category": "Images", "length": 3000, "offset": 100, "confidence": 0.8},
        {"filename": "a_file.png", "extension": "png", "category": "Images", "length": 1000, "offset": 50, "confidence": 0.9},
        {"filename": "c_file.png", "extension": "png", "category": "Images", "length": 2000, "offset": 200, "confidence": 0.7},
    ]
    model.set_items(items)

    # Sort by filename ascending (col 1)
    model.sort(1, Qt.SortOrder.AscendingOrder)
    assert model.get_item(0).filename == "a_file.png"
    assert model.get_item(2).filename == "c_file.png"

    # Sort by size ascending (col 5)
    model.sort(5, Qt.SortOrder.AscendingOrder)
    assert model.get_item(0).size_bytes == 1000
    assert model.get_item(2).size_bytes == 3000

    # Sort by size descending (col 5)
    model.sort(5, Qt.SortOrder.DescendingOrder)
    assert model.get_item(0).size_bytes == 3000
    assert model.get_item(2).size_bytes == 1000

def test_recovery_orchestrator_synthetic(tmp_path: Path):
    """Verifies RecoveryOrchestrator scanning a synthetic image and generating unified artifact models."""
    from engine.orchestrator import RecoveryOrchestrator
    img = tmp_path / "test_orch.img"
    png_bytes = create_synthetic_png()
    buf = bytearray(b"\x00" * 256)
    buf.extend(png_bytes)
    buf.extend(b"\x00" * 256)
    img.write_bytes(buf)

    orchestrator = RecoveryOrchestrator(use_native_carver=True, use_photorec=False, use_tsk=False)
    discovered = orchestrator.scan(img)

    assert len(discovered) == 1
    art = discovered[0]
    assert art["extension"] == "png"
    assert art["recovery_engine"] == "RecoverX Carver"
    assert art["offset"] == 256
    assert art["is_valid"] is True
    assert art["sha256"] == compute_sha256(png_bytes)

def test_selective_extraction_and_verification(tmp_path: Path):
    """Verifies selective artifact extraction, destination isolation, and post-write SHA-256 verification."""
    img = tmp_path / "source.img"
    png_bytes = create_synthetic_png()
    jpg_bytes = create_synthetic_jpg()

    buf = bytearray(b"\x00" * 128)
    buf.extend(png_bytes)
    buf.extend(b"\x00" * 128)
    buf.extend(jpg_bytes)
    img.write_bytes(buf)

    scanner = SignatureScanner()
    carved = scanner.scan_image_file(img)
    assert len(carved) == 2

    # Recover only the PNG item
    png_item = next(c for c in carved if c.extension == "png")
    out_dir = tmp_path / "recovered_dest"
    rec_mgr = RecoveryManager(output_dir=out_dir)

    results = rec_mgr.recover_artifacts(
        artifacts=[png_item],
        source_path=img,
        skip_duplicates=True
    )

    assert results["total_selected"] == 1
    assert results["total_recovered"] == 1
    assert results["verified_success"] == 1
    assert results["failed_count"] == 0

    written_file = Path(results["files"][0]["path"])
    assert written_file.exists()
    assert compute_sha256(written_file) == compute_sha256(png_bytes)

def test_reports_view_and_export(qapp, tmp_path: Path):
    """Verifies ReportsView initializes, loads reports, and exports safely."""
    from gui.views.reports_view import ReportsView
    view = ReportsView()
    assert view is not None
    assert view.reports_table.columnCount() == 4
    assert view.tabs.count() == 2
    view.close()

def test_donut_chart_widget(qapp):
    """Verifies FileTypesDonutWidget rendering and data updating."""
    from gui.widgets.donut_chart import FileTypesDonutWidget
    counts = {"Images": 3, "Documents": 2, "Archives": 1, "Videos": 0, "Audio": 0}
    widget = FileTypesDonutWidget(counts)
    assert widget is not None
    assert widget.counts["Images"] == 3
    widget.update_data({"Images": 10, "Documents": 5, "Archives": 2, "Videos": 1, "Audio": 0})
    assert widget.counts["Images"] == 10
    widget.close()

def test_dashboard_navigation_signals(qapp):
    """Verifies that DashboardView quick action buttons emit navigation signals."""
    from gui.views.dashboard_view import DashboardView
    dash = DashboardView()

    nav_called = []
    dash.navigate_to_recovery.connect(lambda: nav_called.append("recovery"))
    dash.navigate_to_history.connect(lambda: nav_called.append("history"))
    dash.navigate_to_settings.connect(lambda: nav_called.append("settings"))

    dash.btn_new_inv.click()
    assert "recovery" in nav_called

    dash.btn_photorec_cfg.click()
    assert "settings" in nav_called

    dash.close()

def test_whatsapp_view_population_and_stages(qapp, tmp_path):
    """Verifies that WhatsAppView initializes, populates tables, and displays encryption/correlation stages."""
    from gui.views.whatsapp_view import WhatsAppView
    wa_view = WhatsAppView()
    assert wa_view is not None
    assert wa_view.tabs.count() == 3

    # Create synthetic WhatsApp scan results
    synthetic_results = {
        "status": "success",
        "target_root": str(tmp_path),
        "media_summary": {
            "categories": {"WhatsApp Images": 2, "WhatsApp Documents": 1}
        },
        "media_correlation": {
            "database_referenced_count": 1,
            "transcript_referenced_count": 1,
            "orphaned_media_count": 1
        },
        "databases": [
            {
                "database_info": {"filename": "msgstore.db.crypt14", "size_bytes": 1024},
                "analysis": {"is_encrypted": True, "format": "WhatsApp Encrypted Backup (crypt14)"},
                "backup_classification": {"classification": "ENCRYPTED_VALID_HEADER", "cipher_suite": "AES-256-GCM"}
            },
            {
                "database_info": {"filename": "msgstore.db", "size_bytes": 4096},
                "analysis": {"is_encrypted": False, "format": "SQLite format 3 (Plaintext)", "statistics": {"messages_count": 25}},
                "backup_classification": {"classification": "DECRYPTED_PLAINTEXT", "cipher_suite": "Plaintext"}
            }
        ],
        "chat_exports": [
            {
                "filename": "WhatsApp Chat with Alice.txt",
                "total_messages": 10,
                "participants": ["Alice", "Bob"],
                "attachments_referenced": [{"filename": "photo.jpg"}]
            }
        ]
    }

    wa_view.current_scan_results = synthetic_results
    wa_view._populate_results(synthetic_results)

    # Check media table
    assert wa_view.media_table.rowCount() == 2
    # Check databases table
    assert wa_view.db_table.rowCount() == 2
    assert "crypt14" in wa_view.db_table.item(0, 0).text()
    assert "msgstore.db" in wa_view.db_table.item(1, 0).text()
    # Check chats table
    assert wa_view.chats_table.rowCount() == 1
    assert "Alice" in wa_view.chats_table.item(0, 2).text()

    wa_view.close()



