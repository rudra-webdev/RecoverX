"""
RecoverX Persistent History Manager
Stores forensic investigation sessions, carved artifact records, cryptographic checksums,
and execution metadata in a local SQLite database (reports/recoverx_history.db).

Provides query interfaces for:
- Dashboard statistics (discovered/recovered totals, file-type distributions)
- Recent activity feeds
- Historical investigation sessions and file lists
"""
import sqlite3
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from config import REPORTS_DIR

DB_PATH = REPORTS_DIR / "recoverx_history.db"

class HistoryManager:
    """Manages persistent SQLite storage of forensic recovery sessions."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self):
        """Initializes tables for investigations and file records."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    source_path TEXT,
                    source_type TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    engines_used TEXT,
                    files_discovered INTEGER DEFAULT 0,
                    files_recovered INTEGER DEFAULT 0,
                    files_validated INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'Completed',
                    output_dir TEXT,
                    report_path TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS investigation_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    extension TEXT,
                    category TEXT,
                    size_bytes INTEGER DEFAULT 0,
                    offset INTEGER DEFAULT 0,
                    sha256 TEXT,
                    status TEXT DEFAULT 'verified',
                    verified INTEGER DEFAULT 1,
                    engine TEXT DEFAULT 'RecoverX Carver',
                    FOREIGN KEY (investigation_id) REFERENCES investigations (id) ON DELETE CASCADE
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_inv_timestamp ON investigations(timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_inv ON investigation_files(investigation_id)")
            conn.commit()

    def record_investigation(
        self,
        source_name: str,
        source_path: str,
        source_type: str,
        scan_mode: str,
        engines_used: str,
        files_discovered: int,
        files_recovered: int,
        files_validated: int = 0,
        total_bytes: int = 0,
        status: str = "Completed",
        output_dir: str = "",
        report_path: str = "",
        session_id: Optional[str] = None
    ) -> int:
        """Records a new investigation session and returns its ID."""
        now = datetime.datetime.now()
        dt_str = now.isoformat()
        if not session_id:
            session_id = f"INV-{now.strftime('%Y%m%d_%H%M%S')}_{now.microsecond:06d}"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO investigations (
                    session_id, timestamp, source_name, source_path, source_type,
                    scan_mode, engines_used, files_discovered, files_recovered,
                    files_validated, total_bytes, status, output_dir, report_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, dt_str, source_name, source_path, source_type,
                scan_mode, engines_used, files_discovered, files_recovered,
                files_validated, total_bytes, status, output_dir, report_path
            ))
            conn.commit()
            return cursor.lastrowid

    def record_investigation_files(self, investigation_id: int, files: List[Dict[str, Any]]) -> int:
        """Bulk inserts file records associated with an investigation."""
        if not files:
            return 0

        with self._get_connection() as conn:
            cursor = conn.cursor()
            records = []
            for f in files:
                records.append((
                    investigation_id,
                    f.get("filename", "unknown"),
                    f.get("extension", ""),
                    f.get("category", "Other"),
                    int(f.get("size_bytes", 0) or f.get("size", 0) or 0),
                    int(f.get("offset", 0) or 0),
                    f.get("sha256", ""),
                    f.get("status", "verified"),
                    1 if f.get("status") in ("verified", "valid", "Recovered", "recovered") else 0,
                    f.get("engine", "RecoverX Carver")
                ))
            cursor.executemany("""
                INSERT INTO investigation_files (
                    investigation_id, filename, extension, category,
                    size_bytes, offset, sha256, status, verified, engine
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
            conn.commit()
            return len(records)

    def get_all_investigations(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns all recorded investigations in reverse chronological order."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM investigations
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_investigation_by_id(self, investigation_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a single investigation record by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_investigation_files(self, investigation_id: int) -> List[Dict[str, Any]]:
        """Retrieves all file records associated with an investigation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM investigation_files
                WHERE investigation_id = ?
                ORDER BY id ASC
            """, (investigation_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_total_stats(self) -> Dict[str, Any]:
        """
        Dynamically computes cumulative statistics across all investigations:
        - total_discovered
        - total_recovered
        - total_validated
        - type_distribution
        - recent_activities
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Cumulative discovered & recovered
            cursor.execute("""
                SELECT 
                    COALESCE(SUM(files_discovered), 0) as total_discovered,
                    COALESCE(SUM(files_recovered), 0) as total_recovered,
                    COALESCE(SUM(files_validated), 0) as total_validated,
                    COALESCE(SUM(total_bytes), 0) as total_bytes,
                    COUNT(id) as total_sessions
                FROM investigations
            """)
            summary_row = dict(cursor.fetchone())

            # File types distribution from carved files
            cursor.execute("""
                SELECT category, COUNT(id) as cnt
                FROM investigation_files
                GROUP BY category
            """)
            category_counts = {row["category"]: row["cnt"] for row in cursor.fetchall()}

            distribution = {
                "Images": category_counts.get("Images", 0) + category_counts.get("Image", 0),
                "Documents": category_counts.get("Documents", 0) + category_counts.get("Document", 0),
                "Archives": category_counts.get("Archives", 0) + category_counts.get("Archive", 0),
                "Videos": category_counts.get("Videos", 0) + category_counts.get("Video", 0),
                "Audio": category_counts.get("Audio", 0)
            }

            # If no files in database yet, but sessions exist, check extensions
            cursor.execute("""
                SELECT * FROM investigations
                ORDER BY id DESC
                LIMIT 5
            """)
            recent_invs = [dict(r) for r in cursor.fetchall()]

            return {
                "total_discovered": summary_row["total_discovered"],
                "total_recovered": summary_row["total_recovered"],
                "total_validated": summary_row["total_validated"],
                "total_bytes": summary_row["total_bytes"],
                "total_sessions": summary_row["total_sessions"],
                "type_distribution": distribution,
                "recent_investigations": recent_invs
            }

    def clear_history(self):
        """Clears all historical records (used for test setup/teardown)."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM investigation_files")
            conn.execute("DELETE FROM investigations")
            conn.commit()
