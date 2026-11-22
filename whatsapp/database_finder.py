"""
WhatsApp Database Finder for RecoverX
Locates unencrypted and encrypted database artifacts across filesystem trees.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional
import os
import re

DATABASE_PATTERNS = [
    r"^msgstore\.db$",
    r"^msgstore\.db\.crypt(\d+)$",
    r"^msgstore-(\d{4}-\d{2}-\d{2})\.(\d+)\.db\.crypt(\d+)$",
    r"^msgstore-(\d{4}-\d{2}-\d{2})\.(\d+)\.db$",
    r"^wa\.db$",
    r"^wa\.db\.crypt(\d+)$",
    r"^chatsettingsbackup\.db\.crypt(\d+)$",
    r"^stickers\.db$"
]

class WhatsAppDatabaseItem:
    def __init__(
        self,
        path: Path,
        filename: str,
        size_bytes: int,
        crypt_version: Optional[int],
        is_encrypted: bool,
        backup_date: Optional[str]
    ):
        self.path = path
        self.filename = filename
        self.size_bytes = size_bytes
        self.crypt_version = crypt_version
        self.is_encrypted = is_encrypted
        self.backup_date = backup_date

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "crypt_version": self.crypt_version,
            "is_encrypted": self.is_encrypted,
            "backup_date": self.backup_date
        }

class WhatsAppDatabaseFinder:
    def __init__(self, search_root: Path):
        self.search_root = Path(search_root)

    def find_databases(self) -> List[WhatsAppDatabaseItem]:
        """Locates all WhatsApp databases under search_root."""
        results: List[WhatsAppDatabaseItem] = []
        if not self.search_root.exists():
            return results

        date_pattern = re.compile(r"(\d{4}-\d{2}-\d{2})")
        crypt_pattern = re.compile(r"\.crypt(\d+)")

        for root, dirs, files in os.walk(self.search_root):
            for file_name in files:
                file_lower = file_name.lower()
                if "msgstore" in file_lower or "wa.db" in file_lower or "chatsettings" in file_lower:
                    file_path = Path(root) / file_name
                    try:
                        sz = file_path.stat().st_size
                    except (OSError, FileNotFoundError):
                        sz = 0

                    crypt_match = crypt_pattern.search(file_name)
                    crypt_ver = int(crypt_match.group(1)) if crypt_match else None
                    is_encrypted = crypt_ver is not None or file_name.endswith(".crypt")

                    date_match = date_pattern.search(file_name)
                    b_date = date_match.group(1) if date_match else None

                    item = WhatsAppDatabaseItem(
                        path=file_path,
                        filename=file_name,
                        size_bytes=sz,
                        crypt_version=crypt_ver,
                        is_encrypted=is_encrypted,
                        backup_date=b_date
                    )
                    results.append(item)

        return results

