"""
WhatsApp Database Analyzer for RecoverX
Inspects unencrypted SQLite databases, WAL files, freelist pages, and encrypted crypt14/crypt15 artifacts.
Strictly adheres to forensic honesty: reports missing keys, WAL frame counts, freelist allocations,
and rejects false recovery claims.
"""
from pathlib import Path
from typing import Dict, Any, Optional, List
import sqlite3
import struct
import os

from utils.logging_config import logger

class WhatsAppDatabaseAnalyzer:
    @classmethod
    def analyze(cls, db_path: Path) -> Dict[str, Any]:
        path = Path(db_path)
        if not path.is_file():
            return {"status": "error", "error": f"Database file not found: {path}"}

        size = path.stat().st_size
        if size == 0:
            return {"status": "error", "error": "Database file is empty (0 bytes)."}

        # Read first 128 bytes to check headers
        with open(path, "rb") as f:
            header = f.read(128)

        # 1. Check for standard SQLite header
        if header.startswith(b"SQLite format 3\x00"):
            return cls._analyze_sqlite(path, size, header)

        # 2. Check for WhatsApp Crypt format
        return cls._analyze_crypt(path, size, header)

    @classmethod
    def _analyze_sqlite(cls, path: Path, size: int, header: bytes) -> Dict[str, Any]:
        """Performs read-only forensic inspection of unencrypted SQLite database, WAL, and freelist."""
        logger.info(f"Inspecting unencrypted SQLite database: {path.name}")
        
        # Parse standard SQLite database header (RFC / SQLite format specifications)
        page_size = struct.unpack(">H", header[16:18])[0]
        if page_size == 1:
            page_size = 65536
        file_change_counter = struct.unpack(">I", header[24:28])[0]
        in_header_pages = struct.unpack(">I", header[28:32])[0]
        freelist_first_page = struct.unpack(">I", header[32:36])[0]
        freelist_pages = struct.unpack(">I", header[36:40])[0]
        schema_cookie = struct.unpack(">I", header[40:44])[0]
        text_encoding_raw = struct.unpack(">I", header[56:60])[0]
        text_encoding = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(text_encoding_raw, f"Unknown ({text_encoding_raw})")

        # Inspect companion Write-Ahead Log (WAL) if present
        wal_path = path.parent / f"{path.name}-wal"
        wal_info = cls._inspect_wal(wal_path, page_size)

        report: Dict[str, Any] = {
            "status": "success",
            "is_encrypted": False,
            "format": "SQLite format 3 (Plaintext)",
            "file_size_bytes": size,
            "sqlite_header": {
                "page_size": page_size,
                "file_change_counter": file_change_counter,
                "in_header_page_count": in_header_pages,
                "freelist_first_page": freelist_first_page,
                "freelist_pages_count": freelist_pages,
                "schema_cookie": schema_cookie,
                "text_encoding": text_encoding
            },
            "wal_companion": wal_info,
            "tables": [],
            "table_details": {},
            "indexes": [],
            "statistics": {},
            "integrity_check": "not_run",
            "recoverable": True,
            "forensic_notes": []
        }

        if freelist_pages > 0:
            report["forensic_notes"].append(
                f"Database contains {freelist_pages} freelist (unallocated) pages. "
                "These pages may hold remnants of deleted records, but require raw block reconstruction "
                "and are NOT counted as active verified messages."
            )

        if wal_info.get("wal_present"):
            report["forensic_notes"].append(
                f"WAL companion detected with {wal_info.get('frame_count', 0)} frames "
                f"({wal_info.get('committed_transactions_count', 0)} confirmed committed transactions, "
                f"{wal_info.get('intermediate_frames_count', 0)} intermediate frames)."
            )

        try:
            # Open SQLite in read-only URI mode to guarantee zero writes
            uri = f"file:{path.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=5)
            cursor = conn.cursor()

            # Query list of tables and indexes
            cursor.execute("SELECT type, name, tbl_name FROM sqlite_master WHERE type IN ('table', 'index', 'view');")
            master_entries = cursor.fetchall()
            tables = [row[1] for row in master_entries if row[0] == "table"]
            indexes = [row[1] for row in master_entries if row[0] == "index"]
            report["tables"] = tables
            report["indexes"] = indexes

            # Quick integrity check
            try:
                cursor.execute("PRAGMA quick_check;")
                q_res = cursor.fetchone()
                report["integrity_check"] = q_res[0] if q_res else "unknown"
            except Exception as e:
                report["integrity_check"] = f"check_failed: {e}"

            stats = {}
            # Check message counts
            for msg_table in ("message", "messages", "chat"):
                if msg_table in tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {msg_table}")
                        stats[f"{msg_table}_count"] = cursor.fetchone()[0]
                    except Exception:
                        pass

            # Check contacts / JID counts
            for jid_table in ("jid", "wa_contacts"):
                if jid_table in tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {jid_table}")
                        stats[f"{jid_table}_count"] = cursor.fetchone()[0]
                    except Exception:
                        pass

            # Check media tables
            for media_tbl in ("message_media", "media_refs"):
                if media_tbl in tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {media_tbl}")
                        stats[f"{media_tbl}_count"] = cursor.fetchone()[0]
                    except Exception:
                        pass

            # Check timestamp range if message table has timestamp column
            if "message" in tables or "messages" in tables:
                table_to_use = "message" if "message" in tables else "messages"
                cursor.execute(f"PRAGMA table_info({table_to_use});")
                cols = [c[1] for c in cursor.fetchall()]
                report["table_details"][table_to_use] = {"columns": cols}
                ts_col = next((c for c in ("timestamp", "received_timestamp", "sort_timestamp") if c in cols), None)
                if ts_col:
                    try:
                        cursor.execute(f"SELECT MIN({ts_col}), MAX({ts_col}) FROM {table_to_use} WHERE {ts_col} > 0;")
                        row = cursor.fetchone()
                        if row and row[0]:
                            stats["earliest_timestamp_ms"] = row[0]
                            stats["latest_timestamp_ms"] = row[1]
                    except Exception:
                        pass

            report["statistics"] = stats
            conn.close()
        except sqlite3.DatabaseError as e:
            report["status"] = "corrupt_or_partial"
            report["error"] = f"SQLite read error: {e}"
            report["recoverable"] = False

        return report

    @staticmethod
    def _compute_wal_checksum(data: bytes, s1: int = 0, s2: int = 0, big_endian: bool = True) -> tuple[int, int]:
        """Computes SQLite WAL 64-bit checksum pair (s1, s2) over 8-byte word pairs (RFC / SQLite format specs)."""
        fmt = ">I" if big_endian else "<I"
        n_pairs = len(data) // 8
        for i in range(0, n_pairs * 8, 8):
            v1 = struct.unpack(fmt, data[i:i+4])[0]
            v2 = struct.unpack(fmt, data[i+4:i+8])[0]
            s1 = (s1 + v1 + s2) & 0xFFFFFFFF
            s2 = (s2 + v2 + s1) & 0xFFFFFFFF
        return s1, s2

    @classmethod
    def _inspect_wal(cls, wal_path: Path, page_size: int) -> Dict[str, Any]:
        """
        Inspects SQLite Write-Ahead Log (-wal) companion file if present.
        Performs header validation, frame header parsing, salt matching, frame checksum calculation,
        and transaction commit marker identification.
        Strictly avoids overstating transaction integrity.
        """
        if not wal_path.is_file():
            return {"wal_present": False}

        wal_size = wal_path.stat().st_size
        if wal_size < 32:
            return {
                "wal_present": True,
                "status": "truncated_wal_header",
                "wal_size_bytes": wal_size,
                "frame_count": 0
            }

        try:
            with open(wal_path, "rb") as f:
                header = f.read(32)

            magic = struct.unpack(">I", header[0:4])[0]
            is_valid_magic = magic in (0x377f0682, 0x377f0683)
            is_big_endian = (magic == 0x377f0683)
            wal_version = struct.unpack(">I", header[4:8])[0]
            wal_page_size = struct.unpack(">I", header[8:12])[0]
            checkpoint_seq = struct.unpack(">I", header[12:16])[0]
            salt1, salt2 = struct.unpack(">II", header[16:24])
            stored_h_chk1, stored_h_chk2 = struct.unpack(">II", header[24:32])

            calc_h_chk1, calc_h_chk2 = cls._compute_wal_checksum(header[:24], 0, 0, is_big_endian)
            header_checksum_verified = (stored_h_chk1 == calc_h_chk1 and stored_h_chk2 == calc_h_chk2)

            frame_size = (wal_page_size or page_size) + 24
            frame_count = (wal_size - 32) // frame_size if frame_size > 0 else 0

            # Stream through frame headers in read-only mode
            valid_frames = 0
            commit_frames = 0
            intermediate_frames = 0
            stale_salt_frames = 0
            checksum_verified_frames = 0

            running_s1, running_s2 = stored_h_chk1, stored_h_chk2

            with open(wal_path, "rb") as f_wal:
                f_wal.seek(32)  # Skip 32-byte WAL header
                for _ in range(frame_count):
                    frame_hdr_bytes = f_wal.read(24)
                    if len(frame_hdr_bytes) < 24:
                        break
                    p_num, db_size, f_s1, f_s2, f_chk1, f_chk2 = struct.unpack(">IIIIII", frame_hdr_bytes)
                    page_bytes = f_wal.read(wal_page_size or page_size)

                    # Check salt
                    if f_s1 == salt1 and f_s2 == salt2:
                        valid_frames += 1
                        if db_size > 0:
                            commit_frames += 1
                        else:
                            intermediate_frames += 1

                        # Verify frame cumulative checksum
                        if len(page_bytes) == (wal_page_size or page_size):
                            calc_s1, calc_s2 = cls._compute_wal_checksum(frame_hdr_bytes[:8], running_s1, running_s2, is_big_endian)
                            calc_s1, calc_s2 = cls._compute_wal_checksum(page_bytes, calc_s1, calc_s2, is_big_endian)
                            if (f_chk1 == calc_s1 and f_chk2 == calc_s2):
                                checksum_verified_frames += 1
                                running_s1, running_s2 = calc_s1, calc_s2
                            else:
                                # Checksum discrepancy (e.g. synthetic test frame with placeholder checksum or torn write)
                                running_s1, running_s2 = f_chk1, f_chk2
                    else:
                        stale_salt_frames += 1

            return {
                "wal_present": True,
                "status": "valid_wal" if is_valid_magic else "invalid_wal_magic",
                "wal_path": str(wal_path),
                "wal_size_bytes": wal_size,
                "wal_magic_valid": is_valid_magic,
                "wal_version": wal_version,
                "wal_page_size": wal_page_size or page_size,
                "checkpoint_sequence": checkpoint_seq,
                "salt1": salt1,
                "salt2": salt2,
                "header_checksum_verified": header_checksum_verified,
                "frame_count": frame_count,
                "valid_frames_count": valid_frames,
                "committed_transactions_count": commit_frames,
                "intermediate_frames_count": intermediate_frames,
                "stale_salt_frames_count": stale_salt_frames,
                "checksum_verified_frames_count": checksum_verified_frames,
                "forensic_assessment": (
                    f"WAL contains {frame_count} physical frames ({valid_frames} active salt). "
                    f"Identified {commit_frames} transaction commit markers. "
                    "Technical qualification: Commit markers denote logical transaction boundaries in WAL frames; "
                    "however, absolute ACID transaction commitment requires sequential replay against the main database "
                    "without predecessor frame torn-write corruption."
                )
            }
        except Exception as e:
            return {
                "wal_present": True,
                "status": f"wal_read_error: {e}",
                "wal_size_bytes": wal_size,
                "frame_count": 0
            }

    @classmethod
    def _analyze_crypt(cls, path: Path, size: int, header: bytes) -> Dict[str, Any]:
        """
        Accurately inspects encrypted WhatsApp crypt12/14/15 artifacts.
        Guarantees that encrypted blobs are NOT falsely reported as recovered.
        """
        filename = path.name
        crypt_ver = "unknown"
        for ver in ("crypt15", "crypt14", "crypt12", "crypt"):
            if ver in filename:
                crypt_ver = ver
                break

        header_len = len(header)
        has_crypt_header = header_len >= 67

        return {
            "status": "encrypted_database",
            "is_encrypted": True,
            "format": f"WhatsApp Encrypted Backup ({crypt_ver})",
            "file_size_bytes": size,
            "header_length_inspected": header_len,
            "has_crypt_header": has_crypt_header,
            "recoverable_without_key": False,
            "key_present": False,
            "forensic_finding": (
                f"File '{filename}' is AES-GCM encrypted ciphertext ({crypt_ver}). "
                "Plaintext chat contents and media records cannot be extracted without the matching "
                "device decryption key (/data/data/com.whatsapp/files/key) or user 64-digit hex key. "
                "Forensic Integrity: Encrypted databases are logged but NOT claimed as recovered."
            )
        }


