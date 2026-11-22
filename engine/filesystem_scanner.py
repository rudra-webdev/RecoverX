"""
Filesystem Scanner for RecoverX
Recursively inspects filesystems, identifying file metadata, hidden caches, and signature mismatches.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional
import os
import datetime

from utils.hashing import compute_sha256
from engine.file_validator import FileValidator
from utils.logging_config import logger

class DiscoveredFile:
    def __init__(
        self,
        path: Path,
        size: int,
        created: float,
        modified: float,
        extension: str,
        is_hidden: bool,
        is_cache_or_thumbnail: bool,
        sha256: Optional[str] = None,
        detected_type: Optional[str] = None,
        mismatch: bool = False
    ):
        self.path = path
        self.size = size
        self.created = created
        self.modified = modified
        self.extension = extension
        self.is_hidden = is_hidden
        self.is_cache_or_thumbnail = is_cache_or_thumbnail
        self.sha256 = sha256
        self.detected_type = detected_type
        self.mismatch = mismatch

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "size": self.size,
            "created": datetime.datetime.fromtimestamp(self.created).isoformat() if self.created else None,
            "modified": datetime.datetime.fromtimestamp(self.modified).isoformat() if self.modified else None,
            "extension": self.extension,
            "is_hidden": self.is_hidden,
            "is_cache_or_thumbnail": self.is_cache_or_thumbnail,
            "sha256": self.sha256,
            "detected_type": self.detected_type,
            "mismatch": self.mismatch
        }

class FilesystemScanner:
    CACHE_KEYWORDS = [".thumbnails", ".thumb", ".cache", "cache", "trash", ".trashed", "lost.dir"]

    def __init__(self, compute_hashes: bool = False, validate_signatures: bool = True):
        self.compute_hashes = compute_hashes
        self.validate_signatures = validate_signatures

    def scan_directory(self, target_dir: Path, max_files: int = 50000) -> List[DiscoveredFile]:
        """Recursively scans target directory with safety boundaries."""
        results: List[DiscoveredFile] = []
        target = Path(target_dir)

        if not target.exists() or not target.is_dir():
            logger.warning(f"Target directory does not exist or is not a directory: {target}")
            return results

        count = 0
        for root, dirs, files in os.walk(target):
            root_path = Path(root)
            is_cache_folder = any(kw in root_path.as_posix().lower() for kw in self.CACHE_KEYWORDS)

            for file_name in files:
                if count >= max_files:
                    logger.warning(f"Reached maximum file scan limit ({max_files})")
                    break

                file_path = root_path / file_name
                try:
                    stat = file_path.stat()
                except (PermissionError, FileNotFoundError):
                    continue

                is_hidden = file_name.startswith(".")
                is_cache = is_cache_folder or is_hidden or any(kw in file_name.lower() for kw in self.CACHE_KEYWORDS)
                ext = file_path.suffix.lstrip(".").lower()

                sha256_hash = None
                if self.compute_hashes:
                    try:
                        sha256_hash = compute_sha256(file_path)
                    except Exception:
                        pass

                detected_type = None
                mismatch = False
                if self.validate_signatures and stat.st_size > 0:
                    try:
                        with open(file_path, "rb") as f:
                            header_bytes = f.read(512)
                        val = FileValidator.validate(header_bytes, ext if ext else "unknown")
                        detected_type = val.get("type")
                        if detected_type and ext and detected_type != ext:
                            # If docx vs zip, not a real conflict
                            if not (ext in ("docx", "xlsx", "pptx") and detected_type == "zip"):
                                mismatch = True
                    except Exception:
                        pass

                item = DiscoveredFile(
                    path=file_path,
                    size=stat.st_size,
                    created=stat.st_ctime,
                    modified=stat.st_mtime,
                    extension=ext,
                    is_hidden=is_hidden,
                    is_cache_or_thumbnail=is_cache,
                    sha256=sha256_hash,
                    detected_type=detected_type,
                    mismatch=mismatch
                )
                results.append(item)
                count += 1

        return results

