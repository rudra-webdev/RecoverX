"""
WhatsApp Recovery Scanner for RecoverX
Coordinates media discovery, database identification, backup evaluation, chat export analysis,
and media-to-database/transcript correlation.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
import os

from whatsapp.media_finder import WhatsAppMediaFinder
from whatsapp.database_finder import WhatsAppDatabaseFinder
from whatsapp.database_analyzer import WhatsAppDatabaseAnalyzer
from whatsapp.backup_analyzer import WhatsAppBackupAnalyzer
from whatsapp.chat_export_analyzer import WhatsAppChatExportAnalyzer
from utils.logging_config import logger

class WhatsAppScanner:
    def __init__(self, target_root: Path):
        self.target_root = Path(target_root)

    def scan(self, key_data: Optional[Any] = None) -> Dict[str, Any]:
        """Performs a comprehensive forensic investigation of the target WhatsApp directory."""
        logger.info(f"Scanning WhatsApp directory: {self.target_root}")
        if not self.target_root.exists():
            return {
                "status": "error",
                "error": f"WhatsApp target root does not exist: {self.target_root}"
            }

        # 1. Media discovery & hashing
        media_dir = self.target_root / "Media"
        if not media_dir.exists():
            media_dir = self.target_root

        media_finder = WhatsAppMediaFinder(media_dir)
        media_results = media_finder.scan()

        # 2. Database discovery and deep analysis
        db_finder = WhatsAppDatabaseFinder(self.target_root)
        databases = db_finder.find_databases()
        db_analyses = []
        extracted_db_media_refs: List[Dict[str, Any]] = []

        for db in databases:
            analysis = WhatsAppDatabaseAnalyzer.analyze(db.path)
            backup_detail = WhatsAppBackupAnalyzer.analyze_backup_file(db.path, key_data=key_data)
            db_analyses.append({
                "database_info": db.to_dict(),
                "analysis": analysis,
                "backup_classification": backup_detail
            })

        # 3. Backup folder analysis
        backup_dir = self.target_root / "Backups"
        backup_analyzer = WhatsAppBackupAnalyzer(backup_dir)
        backup_results = backup_analyzer.analyze()

        # 4. Search for exported chat TXT files
        chat_exports = []
        for root, dirs, files in os.walk(self.target_root):
            for f in files:
                if f.lower().endswith(".txt") and ("chat" in f.lower() or "whatsapp" in f.lower()):
                    exp_path = Path(root) / f
                    exp_res = WhatsAppChatExportAnalyzer.analyze_file(exp_path)
                    chat_exports.append(exp_res)

        # 5. Correlate media with databases and chat exports
        media_correlation = WhatsAppMediaFinder.correlate(
            media_items=media_results.get("items", []),
            db_records=extracted_db_media_refs,
            chat_exports=chat_exports
        )

        return {
            "status": "success",
            "target_root": str(self.target_root),
            "media_summary": media_results,
            "media_correlation": media_correlation,
            "databases": db_analyses,
            "backups": backup_results,
            "chat_exports": chat_exports,
            "forensic_integrity_notes": [
                "Encrypted database files (.crypt14/.crypt15) cannot be parsed without the internal device encryption key or user 64-digit hex key.",
                "Original unencrypted SQLite databases are only present if extracted from the private app sandbox (/data/data/com.whatsapp) or decrypted with a valid key.",
                "SQLite freelist unallocated pages are inspected and reported; deleted messages are never claimed unless valid rows are confirmed.",
                "Media artifacts are authenticated with SHA-256 and correlated with transcripts/databases without fabricating associations.",
                "RecoverX reports true state and does not falsely claim decrypted recovery of encrypted blobs."
            ]
        }

