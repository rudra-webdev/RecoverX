"""
WhatsApp Media Finder and Correlator for RecoverX
Discovers, classifies, hashes (SHA-256), deduplicates, and correlates media artifacts
against unencrypted SQLite database records and exported chat transcripts.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import os
import hashlib

MEDIA_CATEGORIES = {
    "WhatsApp Images": ["jpg", "jpeg"],
    "WhatsApp Video": ["mp4", "3gp", "mkv", "avi"],
    "WhatsApp Audio": ["mp3", "m4a", "aac", "wav", "ogg"],
    "WhatsApp Voice Notes": ["opus", "ogg"],
    "WhatsApp Documents": ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "zip"],
    "WhatsApp Stickers": ["webp"],
    "WhatsApp Animated Gifs": ["mp4", "gif"],
    "WhatsApp Profile Photos": ["jpg", "jpeg"],
    "WhatsApp Wallpapers": ["jpg", "jpeg", "png"]
}

class WhatsAppMediaItem:
    def __init__(
        self,
        category: str,
        path: Path,
        size_bytes: int,
        is_sent: bool,
        is_private: bool,
        is_thumbnail: bool,
        sha256: str = "",
        correlation_status: str = "ORPHANED_MEDIA"
    ):
        self.category = category
        self.path = path
        self.size_bytes = size_bytes
        self.is_sent = is_sent
        self.is_private = is_private
        self.is_thumbnail = is_thumbnail
        self.sha256 = sha256
        self.correlation_status = correlation_status
        self.is_duplicate = False
        self.duplicate_group_size = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "filename": self.path.name,
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "correlation_status": self.correlation_status,
            "is_duplicate": self.is_duplicate,
            "duplicate_group_size": self.duplicate_group_size,
            "is_sent": self.is_sent,
            "is_private": self.is_private,
            "is_thumbnail": self.is_thumbnail
        }

class WhatsAppMediaFinder:
    def __init__(self, media_root: Path):
        self.media_root = Path(media_root)

    @staticmethod
    def calculate_sha256(path: Path) -> str:
        """Calculates streaming SHA-256 checksum for a media file."""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def scan(self) -> Dict[str, Any]:
        """Scans local media directory, categorizes, hashes (SHA-256), and detects duplicates."""
        findings: List[WhatsAppMediaItem] = []
        category_counts: Dict[str, int] = {cat: 0 for cat in MEDIA_CATEGORIES}
        total_size = 0
        hash_to_items: Dict[str, List[WhatsAppMediaItem]] = {}

        if not self.media_root.exists():
            return {
                "status": "not_found",
                "media_root": str(self.media_root),
                "total_count": 0,
                "total_bytes": 0,
                "categories": category_counts,
                "duplicate_count": 0,
                "items": []
            }

        for root, dirs, files in os.walk(self.media_root):
            root_path = Path(root)
            parts = root_path.parts
            is_sent = "Sent" in parts
            is_private = "Private" in parts
            is_thumb = ".thumbnails" in parts or ".thumb" in parts or ".Trash" in parts

            # Identify matching category
            matched_cat = "Other Media"
            for cat in MEDIA_CATEGORIES:
                if cat.lower() in root_path.as_posix().lower():
                    matched_cat = cat
                    break

            for f in files:
                file_path = root_path / f
                try:
                    sz = file_path.stat().st_size
                except (OSError, FileNotFoundError):
                    continue

                file_hash = self.calculate_sha256(file_path)

                item = WhatsAppMediaItem(
                    category=matched_cat,
                    path=file_path,
                    size_bytes=sz,
                    is_sent=is_sent,
                    is_private=is_private,
                    is_thumbnail=is_thumb,
                    sha256=file_hash,
                    correlation_status="ORPHANED_MEDIA"
                )
                findings.append(item)
                if file_hash:
                    hash_to_items.setdefault(file_hash, []).append(item)

                if matched_cat in category_counts:
                    category_counts[matched_cat] += 1
                total_size += sz

        # Identify duplicates
        duplicate_count = 0
        for h, items in hash_to_items.items():
            if len(items) > 1:
                duplicate_count += (len(items) - 1)
                for itm in items:
                    itm.is_duplicate = True
                    itm.duplicate_group_size = len(items)

        return {
            "status": "success",
            "media_root": str(self.media_root),
            "total_count": len(findings),
            "total_bytes": total_size,
            "duplicate_count": duplicate_count,
            "categories": category_counts,
            "items": [item.to_dict() for item in findings],
            "_item_objects": findings  # internal use for correlation
        }

    @classmethod
    def correlate(
        cls,
        media_items: List[Dict[str, Any]],
        db_records: Optional[List[Dict[str, Any]]] = None,
        chat_exports: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Correlates discovered media files against SQLite database records and exported transcripts.
        Strictly distinguishes:
        - CONFIRMED_DB_MATCH (High Confidence): Matched via full path or SHA-256 hash in DB.
        - PROBABLE_TRANSCRIPT_MATCH (Medium Confidence): Attachment referenced in same folder as transcript.
        - WEAK_FILENAME_MATCH (Low Confidence): Filename match only, without path or hash verification.
        - ORPHANED_MEDIA: Valid media file on disk but no corresponding database or chat entry found.
        Never presents a weak filename match as confirmed forensic evidence.
        """
        db_path_matches: Set[str] = set()
        db_hash_matches: Set[str] = set()
        db_generic_filenames: Set[str] = set()

        transcript_resolved_filenames: Set[str] = set()
        transcript_unresolved_filenames: Set[str] = set()

        if db_records:
            for rec in db_records:
                for key in ("file_path", "filename", "media_url", "thumb_image"):
                    val = rec.get(key)
                    if val and isinstance(val, str):
                        clean_path = val.replace("\\", "/").lower()
                        db_path_matches.add(clean_path)
                        db_generic_filenames.add(Path(val).name.lower())
                h_val = rec.get("file_hash") or rec.get("sha256")
                if h_val and isinstance(h_val, str):
                    db_hash_matches.add(h_val.lower())

        if chat_exports:
            for exp in chat_exports:
                for att in exp.get("attachments_referenced", []):
                    fn = att.get("filename")
                    found = att.get("found_on_disk", False)
                    if fn:
                        if found:
                            transcript_resolved_filenames.add(fn.lower())
                        else:
                            transcript_unresolved_filenames.add(fn.lower())

        correlated_items = []
        confirmed_db_count = 0
        probable_trans_count = 0
        weak_filename_count = 0
        orphaned_count = 0

        for itm in media_items:
            fn = itm.get("filename", "").lower()
            fp = itm.get("path", "").replace("\\", "/").lower()
            sha = itm.get("sha256", "").lower()

            itm_copy = dict(itm)

            # 1. Check strong DB match (path or hash)
            if (fp in db_path_matches) or (sha and sha in db_hash_matches):
                itm_copy["correlation_status"] = "DATABASE_REFERENCED"
                itm_copy["correlation_level"] = "CONFIRMED_DB_MATCH"
                itm_copy["confidence"] = "HIGH"
                itm_copy["match_reason"] = "Exact path or cryptographic SHA-256 match in database records."
                confirmed_db_count += 1

            # 2. Check probable transcript match (resolved in folder)
            elif fn in transcript_resolved_filenames:
                itm_copy["correlation_status"] = "TRANSCRIPT_REFERENCED"
                itm_copy["correlation_level"] = "PROBABLE_TRANSCRIPT_MATCH"
                itm_copy["confidence"] = "MEDIUM"
                itm_copy["match_reason"] = "Exported chat transcript explicitly references attachment resolved on disk."
                probable_trans_count += 1

            # 3. Check weak filename match (generic name without verified path/hash)
            elif (fn in db_generic_filenames) or (fn in transcript_unresolved_filenames):
                itm_copy["correlation_status"] = "WEAK_FILENAME_MATCH"
                itm_copy["correlation_level"] = "WEAK_FILENAME_ONLY"
                itm_copy["confidence"] = "LOW"
                itm_copy["match_reason"] = "Filename string match only; no verified path or cryptographic link."
                weak_filename_count += 1

            # 4. Orphaned media
            else:
                itm_copy["correlation_status"] = "ORPHANED_MEDIA"
                itm_copy["correlation_level"] = "ORPHANED"
                itm_copy["confidence"] = "N/A"
                itm_copy["match_reason"] = "No corresponding record found in accessible databases or transcripts."
                orphaned_count += 1

            correlated_items.append(itm_copy)

        return {
            "total_media_inspected": len(media_items),
            "confirmed_db_count": confirmed_db_count,
            "database_referenced_count": confirmed_db_count,  # backward compatibility
            "probable_transcript_count": probable_trans_count,
            "transcript_referenced_count": probable_trans_count,  # backward compatibility
            "weak_filename_matches_count": weak_filename_count,
            "orphaned_media_count": orphaned_count,
            "items": correlated_items,
            "matching_criteria": {
                "high_confidence": "Cryptographic SHA-256 hash or verified filesystem path in SQLite table.",
                "medium_confidence": "Resolved local attachment explicitly referenced in exported transcript timeline.",
                "low_confidence": "Filename-only string coincidence without relational or cryptographic proof (treated with skepticism).",
                "orphaned": "No database or transcript reference located."
            }
        }


