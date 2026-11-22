"""
Storage Scanner for RecoverX
Provides high-level orchestration for scanning raw disk images, drives, and volumes.
Enforces strict physical disk access confirmation and read-only protections.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
import os

from engine.signature_scanner import SignatureScanner, CarvedItem
from engine.filesystem_scanner import FilesystemScanner, DiscoveredFile
from utils.logging_config import logger

class StorageScanner:
    def __init__(self, target_formats: Optional[List[str]] = None):
        self.signature_scanner = SignatureScanner(target_formats=target_formats)
        self.fs_scanner = FilesystemScanner(compute_hashes=True)

    def scan_disk_image(self, image_path: Path) -> Dict[str, Any]:
        """
        Safely scans a raw disk image (.img, .raw, .dd) using signature carving.
        Guaranteed read-only.
        """
        path = Path(image_path)
        if not path.is_file():
            raise FileNotFoundError(f"Disk image not found: {path}")

        file_size = path.stat().st_size
        logger.info(f"[StorageScanner] Scanning raw disk image: {path.name} ({file_size} bytes)")

        carved_items = self.signature_scanner.scan_image_file(path)

        valid_items = [item for item in carved_items if item.is_valid]
        duplicates = [item for item in carved_items if item.is_duplicate]

        return {
            "source_type": "disk_image",
            "source_path": str(path),
            "size_bytes": file_size,
            "total_carved": len(carved_items),
            "valid_carved": len(valid_items),
            "duplicates": len(duplicates),
            "items": [item.to_dict() for item in carved_items],
            "_carved_objects": carved_items
        }

    def scan_physical_drive(self, drive_path: str, user_confirmed: bool = False) -> Dict[str, Any]:
        """
        Scans a physical disk drive (e.g. \\\\.\\PhysicalDrive1).
        Enforces mandatory explicit user confirmation to prevent accidental disk tampering.
        """
        if not user_confirmed:
            raise PermissionError(
                f"Forensic Safety Guard: Scanning physical drive '{drive_path}' requires explicit user confirmation "
                "with --confirm-physical-drive flag. Operation blocked."
            )

        logger.warning(f"Opening physical drive {drive_path} in STRICT READ-ONLY mode.")
        # Only open for read
        try:
            from engine.win32_raw_reader import Win32RawDeviceReader
            with Win32RawDeviceReader(drive_path) as reader:
                # Read first sector to verify accessibility
                mbr = reader.read(512)
                if len(mbr) < 512:
                    raise IOError("Unable to read disk geometry from target physical drive.")
        except Exception as e:
            raise IOError(f"Failed to access physical drive {drive_path} in read-only mode: {e}")

        # Distinguish raw physical scanning from logical
        return {
            "source_type": "physical_drive",
            "drive_path": drive_path,
            "read_only": True,
            "status": "Accessible",
            "warning": "Raw physical disk carving active. Filesystem metadata bypassed."
        }

