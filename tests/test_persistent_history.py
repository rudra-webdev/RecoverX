"""
Automated Tests for RecoverX Persistent History Manager (SQLite)
Tests session recording, file artifact tracking, cumulative dynamic stats,
empty state handling, and multi-instance persistence.
"""
import pytest
from pathlib import Path
import tempfile
import sqlite3

from engine.history_manager import HistoryManager

@pytest.fixture
def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_history.db"
    mgr = HistoryManager(db_path=db_file)
    return mgr

def test_history_manager_initialization_and_tables(temp_db: HistoryManager):
    """Verifies that SQLite tables and indexes are created properly."""
    assert temp_db.db_path.exists()
    with temp_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]
        assert "investigations" in tables
        assert "investigation_files" in tables

def test_empty_state_statistics(temp_db: HistoryManager):
    """Verifies that an empty database yields zero counts and clean empty distributions."""
    stats = temp_db.get_total_stats()
    assert stats["total_discovered"] == 0
    assert stats["total_recovered"] == 0
    assert stats["total_validated"] == 0
    assert stats["total_sessions"] == 0
    assert stats["type_distribution"]["Images"] == 0
    assert stats["type_distribution"]["Documents"] == 0
    assert len(stats["recent_investigations"]) == 0

def test_record_investigation_and_files(temp_db: HistoryManager):
    """Tests recording an investigation session and associated carved files."""
    inv_id = temp_db.record_investigation(
        source_name="evidence_disk.img",
        source_path="/forensics/evidence_disk.img",
        source_type="disk_image",
        scan_mode="Deep Signature Carving",
        engines_used="RecoverX Native Carver",
        files_discovered=10,
        files_recovered=8,
        files_validated=8,
        total_bytes=1048576,
        status="Completed",
        output_dir="/forensics/recovered_01",
        report_path="/forensics/reports/report_01.md"
    )
    assert inv_id == 1

    files = [
        {
            "filename": "carved_000000_photo.jpg",
            "extension": "jpg",
            "category": "Images",
            "size_bytes": 50000,
            "offset": 0,
            "sha256": "abcdef123456",
            "status": "verified"
        },
        {
            "filename": "carved_001000_doc.pdf",
            "extension": "pdf",
            "category": "Documents",
            "size_bytes": 120000,
            "offset": 4096,
            "sha256": "987654fedcba",
            "status": "verified"
        }
    ]
    inserted_count = temp_db.record_investigation_files(inv_id, files)
    assert inserted_count == 2

    # Query investigation
    inv = temp_db.get_investigation_by_id(inv_id)
    assert inv is not None
    assert inv["source_name"] == "evidence_disk.img"
    assert inv["files_discovered"] == 10
    assert inv["files_recovered"] == 8

    # Query files
    stored_files = temp_db.get_investigation_files(inv_id)
    assert len(stored_files) == 2
    assert stored_files[0]["filename"] == "carved_000000_photo.jpg"
    assert stored_files[0]["category"] == "Images"
    assert stored_files[1]["filename"] == "carved_001000_doc.pdf"
    assert stored_files[1]["category"] == "Documents"

def test_cumulative_statistics(temp_db: HistoryManager):
    """Tests that get_total_stats aggregates multiple investigations correctly."""
    temp_db.record_investigation(
        source_name="session1.img",
        source_path="/img1",
        source_type="disk_image",
        scan_mode="Deep Carving",
        engines_used="RecoverX",
        files_discovered=5,
        files_recovered=4,
        files_validated=4,
        total_bytes=4000
    )
    temp_db.record_investigation(
        source_name="session2.img",
        source_path="/img2",
        source_type="disk_image",
        scan_mode="Deep Carving",
        engines_used="RecoverX",
        files_discovered=8,
        files_recovered=6,
        files_validated=6,
        total_bytes=6000
    )

    stats = temp_db.get_total_stats()
    assert stats["total_discovered"] == 13
    assert stats["total_recovered"] == 10
    assert stats["total_validated"] == 10
    assert stats["total_sessions"] == 2
    assert len(stats["recent_investigations"]) == 2

def test_persistence_across_instances(tmp_path: Path):
    """Ensures data persists when opening the SQLite database with a new manager instance."""
    db_file = tmp_path / "persistent_test.db"
    
    # Instance 1: write
    mgr1 = HistoryManager(db_path=db_file)
    mgr1.record_investigation(
        source_name="persistent.raw",
        source_path="/raw",
        source_type="raw_image",
        scan_mode="Multi-Engine",
        engines_used="RecoverX + PhotoRec",
        files_discovered=15,
        files_recovered=12,
        files_validated=12
    )

    # Instance 2: read
    mgr2 = HistoryManager(db_path=db_file)
    invs = mgr2.get_all_investigations()
    assert len(invs) == 1
    assert invs[0]["source_name"] == "persistent.raw"
    assert invs[0]["files_discovered"] == 15
    assert invs[0]["files_recovered"] == 12

def test_history_view_displays_sessions(qapp, tmp_path: Path):
    """Verifies that HistoryView displays SQLite sessions and loads file details on click."""
    from gui.views.history_view import HistoryView
    from unittest.mock import patch

    db_file = tmp_path / "gui_history.db"
    mgr = HistoryManager(db_path=db_file)
    inv_id = mgr.record_investigation(
        source_name="sdcard.raw",
        source_path="/path/to/sdcard.raw",
        source_type="disk_image",
        scan_mode="Deep Carving",
        engines_used="RecoverX Native",
        files_discovered=3,
        files_recovered=2,
        files_validated=2,
        status="Completed"
    )
    mgr.record_investigation_files(inv_id, [
        {"filename": "img01.jpg", "category": "Images", "size_bytes": 1024, "status": "verified", "sha256": "abc"},
        {"filename": "doc01.pdf", "category": "Documents", "size_bytes": 2048, "status": "verified", "sha256": "def"}
    ])

    with patch("gui.views.history_view.HistoryManager", return_value=mgr):
        view = HistoryView()
        assert view.sessions_table.rowCount() == 1
        assert view.sessions_table.item(0, 2).text() == "sdcard.raw"

        # Select row 0
        view.sessions_table.selectRow(0)
        view._on_session_selected()

        detail_text = view.sess_detail_text.toPlainText()
        assert "sdcard.raw" in detail_text
        assert "img01.jpg" in detail_text
        assert "doc01.pdf" in detail_text

def test_dashboard_empty_and_populated_states(qapp, tmp_path: Path):
    """Verifies that DashboardView displays clean empty state when no scans exist, and updates dynamically."""
    from gui.views.dashboard_view import DashboardView
    from unittest.mock import patch

    # 1. Empty state
    db_file = tmp_path / "dash_empty.db"
    mgr_empty = HistoryManager(db_path=db_file)
    empty_rec_dir = tmp_path / "empty_rec"
    empty_rec_dir.mkdir()

    with patch("gui.views.dashboard_view.HistoryManager", return_value=mgr_empty), \
         patch("gui.views.dashboard_view.RECOVERED_DIR", empty_rec_dir):
        dash = DashboardView()
        assert dash.card_discovered.value_lbl.text() == "0"
        assert dash.card_recovered.value_lbl.text() == "0"
        assert dash.donut_widget.total_files == 0
        # Empty activity container should have 1 child widget (the empty state frame)
        assert dash.activity_container.count() == 1

    # 2. Populated state
    mgr_empty.record_investigation(
        source_name="flash_drive.img",
        source_path="/flash",
        source_type="removable_usb",
        scan_mode="Deep Carving",
        engines_used="RecoverX Native",
        files_discovered=7,
        files_recovered=7,
        files_validated=7,
        status="Completed"
    )
    with patch("gui.views.dashboard_view.HistoryManager", return_value=mgr_empty), \
         patch("gui.views.dashboard_view.RECOVERED_DIR", empty_rec_dir):
        dash.refresh_data()
        assert dash.card_discovered.value_lbl.text() == "7"
        assert dash.card_recovered.value_lbl.text() == "7"
        assert dash.activity_container.count() == 1

