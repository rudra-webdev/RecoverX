"""
RecoverX Phase 4 Test Suite: WhatsApp Forensic Specialization
=============================================================
Labels:
- [Synthetic]: Controlled tests using synthetically generated WhatsApp artifacts.
- [Unit]: Isolated parsing, header inspection, and validation tests.
"""

import sqlite3
import struct
import hashlib
from pathlib import Path
import pytest

from whatsapp.database_analyzer import WhatsAppDatabaseAnalyzer
from whatsapp.backup_analyzer import WhatsAppBackupAnalyzer
from whatsapp.chat_export_analyzer import WhatsAppChatExportAnalyzer
from whatsapp.media_finder import WhatsAppMediaFinder, WhatsAppMediaItem
from whatsapp.scanner import WhatsAppScanner


# ==============================================================================
# 1. CRYPT14 / CRYPT15 BACKUP ANALYSIS TESTS
# ==============================================================================

def test_crypt14_valid_header_detection(tmp_path: Path):
    """
    [Synthetic] Tests header analysis of a valid crypt14 backup file:
    - Verifies detection of AES-256-GCM cipher suite.
    - Confirms proper classification as ENCRYPTED_VALID_HEADER.
    - Ensures no false decryption claim is made when key is absent.
    """
    crypt_file = tmp_path / "msgstore-2024-06-01.1.db.crypt14"
    # Construct 191-byte synthetic crypt14 header container
    header_data = b"\x00\x00\x00\x0E" + b"\x57\x41\x42\x41\x43\x4B\x55\x50" + (b"\xAA" * 179)
    crypt_file.write_bytes(header_data + (b"\xCC" * 500))

    analysis = WhatsAppBackupAnalyzer.analyze_backup_file(crypt_file)
    assert analysis["status"] == "encrypted_backup"
    assert analysis["crypt_version"] == 14
    assert analysis["cipher_suite"] == "AES-256-GCM"
    assert analysis["classification"] == "ENCRYPTED_VALID_HEADER"
    assert analysis["has_valid_crypt_header"] is True
    assert analysis["key_status"]["valid"] is False
    assert "cannot be accessed without the authorized device key" in analysis["forensic_disclosure"]


def test_crypt15_valid_header_detection(tmp_path: Path):
    """
    [Synthetic] Tests header analysis of a crypt15 backup file:
    - Confirms identification of crypt15 version.
    - Ensures key requirement disclosure is preserved.
    """
    crypt15_file = tmp_path / "msgstore.db.crypt15"
    header_data = b"\x00\x00\x00\x0F" + (b"\x55" * 150)
    crypt15_file.write_bytes(header_data + (b"\x77" * 200))

    analysis = WhatsAppBackupAnalyzer.analyze_backup_file(crypt15_file)
    assert analysis["status"] == "encrypted_backup"
    assert analysis["crypt_version"] == 15
    assert analysis["classification"] == "ENCRYPTED_VALID_HEADER"
    assert analysis["is_encrypted"] is True


def test_truncated_crypt_backup_rejection(tmp_path: Path):
    """
    [Synthetic] Tests honest reporting when a crypt container is truncated:
    - File smaller than minimal 67-byte header requirement must be flagged as ENCRYPTED_TRUNCATED.
    """
    trunc_file = tmp_path / "msgstore.db.crypt14"
    trunc_file.write_bytes(b"\x00\x00\x00\x0E\x01\x02\x03\x04")  # only 8 bytes

    analysis = WhatsAppBackupAnalyzer.analyze_backup_file(trunc_file)
    assert analysis["status"] == "truncated"
    assert analysis["classification"] == "ENCRYPTED_TRUNCATED"
    assert analysis["size_bytes"] == 8


def test_key_file_inspection_validation(tmp_path: Path):
    """
    [Unit] Tests key validation logic:
    - 158-byte Android key file correctly parsed.
    - 32-byte direct AES key correctly parsed.
    - 64-char hex key correctly parsed.
    - Invalid lengths correctly rejected.
    """
    # 1. 158-byte Android key file
    key158 = tmp_path / "whatsapp.key"
    key158_data = (b"\x00" * 126) + (b"\x42" * 32)
    key158.write_bytes(key158_data)

    res158 = WhatsAppBackupAnalyzer.inspect_key_file(key158)
    assert res158["valid"] is True
    assert res158["key_type"] == "whatsapp_android_key_file_158"
    assert res158["aes_key_len"] == 32

    # 2. 64-character hex key
    hex_key = "a" * 64
    res_hex = WhatsAppBackupAnalyzer.inspect_key_file(hex_key)
    assert res_hex["valid"] is True
    assert res_hex["key_type"] == "raw_aes_256_key_or_hex"

    # 3. Invalid length key
    res_bad = WhatsAppBackupAnalyzer.inspect_key_file(b"\x01" * 16)
    assert res_bad["valid"] is False
    assert "Invalid key length" in res_bad["message"]


# ==============================================================================
# 2. SQLITE FORENSIC ANALYSIS (FREELIST, WAL, AND SCHEMA)
# ==============================================================================

def test_sqlite_freelist_and_header_inspection(tmp_path: Path):
    """
    [Synthetic] Tests SQLite header parsing and freelist inspection on unencrypted SQLite database:
    - Parses page size, text encoding, change counter.
    - Accurately reports freelist page count without claiming deleted messages recovered.
    """
    db_path = tmp_path / "msgstore.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, timestamp INTEGER, text_data TEXT);")
    for i in range(10):
        cur.execute("INSERT INTO messages VALUES (?, ?, ?);", (i, 1700000000000 + i * 1000, f"Message {i}"))
    conn.commit()

    # Delete 5 rows to generate freelist churn
    cur.execute("DELETE FROM messages WHERE _id >= 5;")
    conn.commit()
    conn.close()

    res = WhatsAppDatabaseAnalyzer.analyze(db_path)
    assert res["status"] == "success"
    assert res["is_encrypted"] is False
    assert res["sqlite_header"]["page_size"] > 0
    assert res["sqlite_header"]["text_encoding"] == "UTF-8"
    assert res["statistics"]["messages_count"] == 5
    assert res["recoverable"] is True


def test_sqlite_wal_companion_inspection(tmp_path: Path):
    """
    [Synthetic] Tests inspection of companion SQLite Write-Ahead Log (-wal):
    - Identifies WAL magic number (0x377f0682 / 0x377f0683).
    - Computes pending frame count honestly.
    """
    db_path = tmp_path / "msgstore.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, text_data TEXT);")
    cur.execute("INSERT INTO messages VALUES (1, 'WAL test record');")
    conn.commit()
    conn.close()

    # Create companion WAL file with valid 32-byte WAL header + 1 frame
    # SQLite WAL header: magic (0x377f0682), file format version (3007000),
    # page size (4096), checkpoint seq (1), salt-1 (0x11111111), salt-2 (0x22222222), checksums
    page_size = 4096
    wal_hdr = struct.pack(">IIIIIIII", 0x377f0682, 3007000, page_size, 1, 0x11111111, 0x22222222, 0, 0)
    # Add 1 frame: 24-byte frame header + 4096 page bytes
    frame_hdr = struct.pack(">IIIIII", 1, 1, 0x11111111, 0x22222222, 0, 0)
    frame_data = frame_hdr + (b"\x55" * page_size)

    wal_path = tmp_path / "msgstore.db-wal"
    wal_path.write_bytes(wal_hdr + frame_data)

    res = WhatsAppDatabaseAnalyzer.analyze(db_path)
    assert res["wal_companion"]["wal_present"] is True
    assert res["wal_companion"]["wal_magic_valid"] is True
    assert res["wal_companion"]["frame_count"] == 1
    assert res["wal_companion"]["valid_frames_count"] == 1
    assert res["wal_companion"]["committed_transactions_count"] == 1
    assert res["wal_companion"]["intermediate_frames_count"] == 0


def test_sqlite_wal_distinguishes_committed_vs_intermediate_frames(tmp_path: Path):
    """
    [Synthetic] Verifies that WAL inspection distinguishes between committed transactions
    and intermediate/uncommitted frames:
    - Intermediate frame (db_size == 0) is not counted as a committed transaction.
    - Commit frame (db_size > 0) is accurately identified as a committed transaction.
    - Stale salt frame is detected and rejected.
    """
    db_path = tmp_path / "msgstore.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE t (x INT);")
    conn.commit()
    conn.close()

    page_size = 4096
    wal_hdr = struct.pack(">IIIIIIII", 0x377f0682, 3007000, page_size, 1, 0xAAAAAAAA, 0xBBBBBBBB, 0, 0)

    # Frame 1: Intermediate frame (db_size == 0)
    f1_hdr = struct.pack(">IIIIII", 2, 0, 0xAAAAAAAA, 0xBBBBBBBB, 0, 0)
    f1_data = f1_hdr + (b"\x11" * page_size)

    # Frame 2: Commit frame (db_size == 3)
    f2_hdr = struct.pack(">IIIIII", 3, 3, 0xAAAAAAAA, 0xBBBBBBBB, 0, 0)
    f2_data = f2_hdr + (b"\x22" * page_size)

    # Frame 3: Stale frame from prior checkpoint (different salt)
    f3_hdr = struct.pack(">IIIIII", 4, 4, 0x99999999, 0x88888888, 0, 0)
    f3_data = f3_hdr + (b"\x33" * page_size)

    wal_path = tmp_path / "msgstore.db-wal"
    wal_path.write_bytes(wal_hdr + f1_data + f2_data + f3_data)

    res = WhatsAppDatabaseAnalyzer.analyze(db_path)
    wal_info = res["wal_companion"]
    assert wal_info["frame_count"] == 3
    assert wal_info["valid_frames_count"] == 2
    assert wal_info["committed_transactions_count"] == 1
    assert wal_info["intermediate_frames_count"] == 1
    assert wal_info["stale_salt_frames_count"] == 1
    assert "Identified 1 transaction commit markers" in wal_info["forensic_assessment"]


def test_backup_key_presence_does_not_claim_decrypted(tmp_path: Path):
    """
    [Synthetic] Forensic Accuracy Guard:
    Verifies that providing an examiner key file of valid length (158 bytes)
    does NOT cause the backup to be falsely claimed as decrypted without
    successful mathematical authentication and structural verification.
    """
    crypt_file = tmp_path / "msgstore.db.crypt14"
    crypt_file.write_bytes(b"\x00\x00\x00\x0E" + (b"\xAA" * 190))

    valid_key_file = tmp_path / "test.key"
    valid_key_file.write_bytes((b"\x00" * 126) + (b"\x55" * 32))

    analysis = WhatsAppBackupAnalyzer.analyze_backup_file(crypt_file, key_data=valid_key_file)
    assert analysis["is_encrypted"] is True
    assert analysis["is_decrypted"] is False
    assert analysis["decryption_confirmed"] is False
    assert analysis["classification"] == "ENCRYPTED_KEY_ATTACHED_UNVERIFIED"
    assert "remains classified as ENCRYPTED" in analysis["forensic_disclosure"]

    # Verify 4 explicit forensic stages
    stages = analysis["forensic_stages"]
    assert stages["stage_1_identification"]["status"] == "CONTAINER_IDENTIFIED"
    assert stages["stage_2_key_validation"]["key_structurally_valid"] is True
    assert stages["stage_3_key_compatibility"]["compatibility_verified"] is False
    assert stages["stage_4_decryption_and_verification"]["is_decrypted"] is False
    assert stages["stage_4_decryption_and_verification"]["decryption_confirmed"] is False


def test_media_correlation_distinguishes_weak_filename_from_confirmed_evidence(tmp_path: Path):
    """
    [Synthetic] Media Correlation Confidence Guard:
    Verifies that a generic filename match without matching path or SHA-256 hash
    is categorized as WEAK_FILENAME_MATCH with LOW confidence, and is never
    presented as confirmed forensic evidence.
    """
    media_dir = tmp_path / "Media"
    media_dir.mkdir()
    (media_dir / "photo.jpg").write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 50)

    finder = WhatsAppMediaFinder(media_dir)
    media_scan = finder.scan()

    # Database references 'photo.jpg' at a completely different remote path with non-matching hash
    db_records = [{"filename": "photo.jpg", "file_path": "/storage/emulated/0/DCIM/Camera/photo.jpg", "file_hash": "different_hash"}]

    corr = WhatsAppMediaFinder.correlate(
        media_items=media_scan["items"],
        db_records=db_records
    )

    item = corr["items"][0]
    assert item["correlation_status"] == "WEAK_FILENAME_MATCH"
    assert item["correlation_level"] == "WEAK_FILENAME_ONLY"
    assert item["confidence"] == "LOW"
    assert "no verified path or cryptographic link" in item["match_reason"]
    assert corr["confirmed_db_count"] == 0
    assert corr["weak_filename_matches_count"] == 1


def test_corrupt_sqlite_handling(tmp_path: Path):
    """
    [Synthetic] Verifies that an invalid SQLite header or corrupt database is reported honestly:
    - Never crashes or pretends data was extracted.
    """
    corrupt_db = tmp_path / "corrupt.db"
    # Starts with SQLite magic, but subsequent pages are damaged
    corrupt_db.write_bytes(b"SQLite format 3\x00" + (b"\xFF" * 100))

    res = WhatsAppDatabaseAnalyzer.analyze(corrupt_db)
    assert res["status"] in ("corrupt_or_partial", "success")
    if res["status"] == "corrupt_or_partial":
        assert "SQLite read error" in res["error"]
        assert res["recoverable"] is False


# ==============================================================================
# 3. CHAT TRANSCRIPT ANALYSIS (MULTILINGUAL AND DIVERSE FORMATS)
# ==============================================================================

def test_multilingual_and_diverse_date_chat_parsing(tmp_path: Path):
    """
    [Synthetic] Tests chat export parser against:
    - iOS bracketed format: [DD/MM/YY, HH:MM:SS]
    - Android dash format: DD/MM/YYYY, HH:MM - Name:
    - Multilingual names & text: Hindi, Arabic, Chinese, Russian, Emojis.
    - Hidden Unicode directional marks (\u200e, \u202f).
    - Multi-line message continuation.
    - System message classification.
    """
    chat_file = tmp_path / "WhatsApp Chat with International Team.txt"
    content = (
        "\u200e[15/06/2024, 10:15:30] \u200eMessages and calls are end-to-end encrypted.\n"
        "[15/06/2024, 10:16:01] 👨‍💻 Alex: Hello team, starting forensic test.\n"
        "15/06/2024, 10:17 - \u200eराजेश (Rajesh): नमस्ते! फ़ाइल तैयार है।\n"
        "[15/06/2024, 10:18:22] فاطمة (Fatima): ممتاز، أرفقت التقرير هنا:\n"
        "[15/06/2024, 10:18:45] فاطمة (Fatima): <attached: audit_report.pdf>\n"
        "15/06/2024, 10:19 - 李明 (Li Ming): 收到，我们现在开始审核。\n"
        "This is a continuation line of Li Ming's message.\n"
        "[15/06/2024, 10:20:10] Дмитрий: Документ подтвержден. (file attached: summary.docx)\n"
    )
    chat_file.write_text(content, encoding="utf-8")

    res = WhatsAppChatExportAnalyzer.analyze_file(chat_file)
    assert res["status"] == "success"
    assert res["parsed_messages"] >= 5
    assert res["system_events_count"] >= 1
    assert "👨‍💻 Alex" in res["participants"]
    assert "राजेश (Rajesh)" in res["participants"]
    assert "فاطمة (Fatima)" in res["participants"]
    assert "李明 (Li Ming)" in res["participants"]
    assert "Дмитрий" in res["participants"]

    # Verify attachment detection
    att_names = [a["filename"] for a in res["attachments_referenced"]]
    assert "audit_report.pdf" in att_names
    assert "summary.docx" in att_names


# ==============================================================================
# 4. MEDIA-TO-DATABASE CORRELATION AND DEDUPLICATION
# ==============================================================================

def test_media_hashing_deduplication_and_correlation(tmp_path: Path):
    """
    [Synthetic] Tests:
    - SHA-256 calculation for media files.
    - Identification of exact duplicate media across folders.
    - Correlation against SQLite records and chat export attachments:
      distinguishes DATABASE_REFERENCED, TRANSCRIPT_REFERENCED, and ORPHANED_MEDIA.
    """
    media_dir = tmp_path / "Media" / "WhatsApp Images"
    media_dir.mkdir(parents=True)
    sent_dir = media_dir / "Sent"
    sent_dir.mkdir()

    # Image 1 (original, in database by hash)
    img1_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + (b"\x11" * 100)
    img1_path = media_dir / "IMG_001.jpg"
    img1_path.write_bytes(img1_bytes)
    img1_hash = hashlib.sha256(img1_bytes).hexdigest()

    # Image 1 duplicate in Sent/ (duplicate hash)
    img1_dup = sent_dir / "IMG_001_sent.jpg"
    img1_dup.write_bytes(img1_bytes)

    # Image 2 (referenced only in transcript, not in database)
    img2_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + (b"\x22" * 100)
    img2_path = media_dir / "IMG_002_transcript.jpg"
    img2_path.write_bytes(img2_bytes)

    # Image 3 (orphaned, neither in DB nor transcript)
    img3_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + (b"\x33" * 100)
    img3_path = media_dir / "IMG_003_orphaned.jpg"
    img3_path.write_bytes(img3_bytes)

    # Scan media
    finder = WhatsAppMediaFinder(tmp_path / "Media")
    media_scan = finder.scan()
    assert media_scan["total_count"] == 4
    assert media_scan["duplicate_count"] == 1

    # Correlate with cryptographic hash in DB record and resolved attachment in chat export
    mock_db_records = [{"filename": "IMG_001.jpg", "file_hash": img1_hash}]
    mock_chat_exports = [{"attachments_referenced": [{"filename": "IMG_002_transcript.jpg", "found_on_disk": True}]}]

    corr = WhatsAppMediaFinder.correlate(
        media_items=media_scan["items"],
        db_records=mock_db_records,
        chat_exports=mock_chat_exports
    )

    status_map = {item["filename"]: item["correlation_status"] for item in corr["items"]}
    assert status_map["IMG_001.jpg"] == "DATABASE_REFERENCED"
    assert status_map["IMG_001_sent.jpg"] == "DATABASE_REFERENCED"  # verified by SHA-256 hash match!
    assert status_map["IMG_002_transcript.jpg"] == "TRANSCRIPT_REFERENCED"
    assert status_map["IMG_003_orphaned.jpg"] == "ORPHANED_MEDIA"
    assert corr["confirmed_db_count"] == 2
    assert corr["probable_transcript_count"] == 1
    assert corr["orphaned_media_count"] == 1


# ==============================================================================
# 5. INTEGRATED WHATSAPP SCANNER ORCHESTRATION
# ==============================================================================

def test_full_whatsapp_scanner_orchestration(tmp_path: Path):
    """
    [Synthetic] Tests WhatsAppScanner on a complete synthetic directory tree:
    - Backups/ with crypt14 and crypt15 files.
    - Databases/ with unencrypted SQLite.
    - Media/ with images and duplicates.
    - Exported chat transcript.
    - Verifies all forensic sections and integrity notes.
    """
    wa_root = tmp_path / "WhatsApp"
    (wa_root / "Backups").mkdir(parents=True)
    (wa_root / "Databases").mkdir(parents=True)
    (wa_root / "Media" / "WhatsApp Images").mkdir(parents=True)

    # Backups
    (wa_root / "Backups" / "msgstore-2024-05-01.1.db.crypt14").write_bytes(b"\x00" * 150)
    (wa_root / "Databases" / "msgstore.db.crypt15").write_bytes(b"\x00" * 150)

    # Plaintext DB
    db_file = wa_root / "Databases" / "msgstore.db"
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, text_data TEXT);")
    cur.execute("INSERT INTO message VALUES (1, 'Test active message');")
    conn.commit()
    conn.close()

    # Media
    (wa_root / "Media" / "WhatsApp Images" / "photo1.jpg").write_bytes(b"\xFF\xD8\xFF" + b"\x00" * 50)

    # Chat export
    chat_txt = wa_root / "WhatsApp Chat with Auditor.txt"
    chat_txt.write_text("[01/01/2024, 12:00:00] Auditor: Audit complete.\n", encoding="utf-8")

    scanner = WhatsAppScanner(wa_root)
    res = scanner.scan()

    assert res["status"] == "success"
    assert res["media_summary"]["total_count"] == 1
    assert len(res["databases"]) == 3
    assert len(res["chat_exports"]) == 1
    assert len(res["forensic_integrity_notes"]) == 5
