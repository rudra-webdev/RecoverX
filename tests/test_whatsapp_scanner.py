"""
Test Suite for WhatsApp Artifact Discovery, Database Analysis, and Chat Export Parsing.
"""
import pytest
import sqlite3
from pathlib import Path
from whatsapp.database_finder import WhatsAppDatabaseFinder
from whatsapp.database_analyzer import WhatsAppDatabaseAnalyzer
from whatsapp.chat_export_analyzer import WhatsAppChatExportAnalyzer
from whatsapp.media_finder import WhatsAppMediaFinder

def test_whatsapp_database_finder(tmp_path: Path):
    wa_dir = tmp_path / "WhatsApp"
    db_dir = wa_dir / "Databases"
    db_dir.mkdir(parents=True)

    # Create dummy database files
    (db_dir / "msgstore.db.crypt14").write_bytes(b"\x00" * 200)
    (db_dir / "msgstore-2023-11-01.1.db.crypt14").write_bytes(b"\x00" * 200)
    (db_dir / "msgstore.db.crypt15").write_bytes(b"\x00" * 200)
    (db_dir / "wa.db").write_bytes(b"\x00" * 100)

    finder = WhatsAppDatabaseFinder(wa_dir)
    found = finder.find_databases()

    assert len(found) == 4
    filenames = [d.filename for d in found]
    assert "msgstore.db.crypt14" in filenames
    assert "msgstore.db.crypt15" in filenames
    assert "msgstore-2023-11-01.1.db.crypt14" in filenames
    assert "wa.db" in filenames

    c14_item = next(d for d in found if d.filename == "msgstore-2023-11-01.1.db.crypt14")
    assert c14_item.crypt_version == 14
    assert c14_item.backup_date == "2023-11-01"
    assert c14_item.is_encrypted is True

def test_unencrypted_sqlite_analyzer(tmp_path: Path):
    db_path = tmp_path / "msgstore.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, timestamp INTEGER, text_data TEXT);")
    cur.execute("INSERT INTO messages VALUES (1, 1699999999000, 'Forensic Test Message');")
    conn.commit()
    conn.close()

    res = WhatsAppDatabaseAnalyzer.analyze(db_path)
    assert res["status"] == "success"
    assert res["is_encrypted"] is False
    assert "messages" in res["tables"]
    assert res["statistics"]["messages_count"] == 1
    assert res["recoverable"] is True

def test_encrypted_crypt14_analyzer(tmp_path: Path):
    crypt_path = tmp_path / "msgstore.db.crypt14"
    # Write crypt header imitation
    crypt_path.write_bytes(b"\x00\x00\x00\x0E" + (b"\xFF" * 150))

    res = WhatsAppDatabaseAnalyzer.analyze(crypt_path)
    assert res["is_encrypted"] is True
    assert res["recoverable_without_key"] is False
    assert res["key_present"] is False
    assert "cannot be extracted without" in res["forensic_finding"]

def test_chat_export_analyzer(tmp_path: Path):
    chat_file = tmp_path / "WhatsApp Chat with Alice.txt"
    content = (
        "[11/15/23, 2:30:15 PM] Alice: Hello, here is the photo.\n"
        "[11/15/23, 2:31:00 PM] Alice: <attached: photo.jpg>\n"
        "[11/15/23, 2:32:10 PM] Bob: Got it! Thanks.\n"
    )
    chat_file.write_text(content, encoding="utf-8")

    # Put the photo file next to it
    (tmp_path / "photo.jpg").write_bytes(b"\xFF\xD8\xFF\xE0" + (b"\x00" * 20))

    analysis = WhatsAppChatExportAnalyzer.analyze_file(chat_file)
    assert analysis["status"] == "success"
    assert analysis["parsed_messages"] == 3
    assert "Alice" in analysis["participants"]
    assert "Bob" in analysis["participants"]
    assert len(analysis["attachments_referenced"]) == 1
    assert analysis["attachments_referenced"][0]["filename"] == "photo.jpg"
    assert analysis["attachments_referenced"][0]["found_on_disk"] is True

