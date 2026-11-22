"""
SD Card Forensic Recovery Coordinator for RecoverX (Mode B)
===========================================================
Manages recovery of lost/deleted data from SD cards, MicroSD cards,
and multimedia cards connected via Windows card readers or USB adapters.

Enforces:
1. Accurate identification of removable SD cards vs fixed storage.
2. Read-only direct access via Win32RawDeviceReader.
3. Bit-stream forensic disk imaging via DiskImager (preventing media wear).
4. Signature carving and filesystem reconstruction for FAT32 and exFAT.
5. Strict output isolation (Source != Destination).
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Union
import os

from engine.drive_manager import DriveManager, StorageSource
from engine.disk_imager import DiskImager
from engine.signature_scanner import SignatureScanner, CarvedItem
from engine.recovery_manager import RecoveryManager
from engine.win32_raw_reader import Win32RawDeviceReader
from utils.logging_config import logger

class SDCardRecoveryManager:
    """Coordinates SD Card discovery, raw imaging, and forensic carving."""

    SD_CARD_HINTS = [
        "sd", "mmc", "card", "microsd", "tf", "transcend",
        "sandisk", "kingston", "lexar", "sony", "samsung", "removable"
    ]

    SUPPORTED_FILESYSTEMS = ["FAT", "FAT32", "exFAT", "RAW"]

    @classmethod
    def detect_sd_cards(cls) -> List[StorageSource]:
        """
        Enumerates removable storage drives on Windows and identifies
        likely SD / MicroSD card media connected via card readers.
        """
        all_sources = DriveManager.list_logical_drives()
        sd_candidates: List[StorageSource] = []

        for src in all_sources:
            if src.source_type == "removable_usb" or src.name.lower().find("card") != -1:
                # Check for SD card hints in volume name or filesystem
                name_lower = src.name.lower()
                is_sd_hint = any(h in name_lower for h in cls.SD_CARD_HINTS)

                # Format identification
                fs_upper = src.filesystem.upper()
                is_supported_fs = any(sfs in fs_upper for sfs in cls.SUPPORTED_FILESYSTEMS)

                # Clone source with specialized source_type
                sd_source = StorageSource(
                    name=f"SD Card: {src.name}",
                    identifier=src.identifier,
                    source_type="sd_card" if is_sd_hint else "removable_usb",
                    filesystem=src.filesystem,
                    total_bytes=src.total_bytes,
                    free_bytes=src.free_bytes,
                    used_bytes=src.used_bytes,
                    is_system_drive=False,
                    is_read_only=True,
                    requires_confirmation=False,
                    model_name=src.name
                )
                sd_candidates.append(sd_source)

        return sd_candidates

    @classmethod
    def create_sd_image(
        cls,
        source: Union[StorageSource, str, Path],
        output_image_path: Union[str, Path],
        progress_callback: Optional[Callable[[int, int, float], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None
    ) -> Dict[str, Any]:
        """
        Creates a bit-stream raw disk image (.raw / .dd) from an SD card.
        Ensures the original SD card is preserved read-only.
        """
        src_path = source.identifier if isinstance(source, StorageSource) else str(source)
        logger.info(f"[SDCardRecovery] Creating forensic bit-stream image of SD card: {src_path}")

        return DiskImager.create_image(
            source_path=src_path,
            output_image_path=output_image_path,
            progress_callback=progress_callback,
            is_cancelled=is_cancelled
        )

    @classmethod
    def scan_and_recover_sd_card(
        cls,
        source: Union[StorageSource, str, Path],
        destination_dir: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        item_callback: Optional[Callable[[CarvedItem], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None
    ) -> Dict[str, Any]:
        """
        Executes read-only signature carving on the SD card (or its image)
        and extracts recovered items to a safe destination directory.
        """
        src_path = source.identifier if isinstance(source, StorageSource) else str(source)
        dest_dir = Path(destination_dir).resolve()

        # Enforce destination safety
        RecoveryManager.validate_destination_safety(Path(src_path), dest_dir)

        # 1. Carve using SignatureScanner (which uses Win32RawDeviceReader)
        scanner = SignatureScanner()
        carved_items = scanner.scan_image_file(
            file_path=src_path,
            progress_callback=progress_callback,
            item_callback=item_callback
        )

        # 2. Extract and verify recovered files
        rec_mgr = RecoveryManager(output_dir=dest_dir)
        recovery_results = rec_mgr.recover_artifacts(
            artifacts=carved_items,
            source_path=Path(src_path),
            skip_duplicates=True,
            only_valid=False,
            is_cancelled_callback=is_cancelled
        )

        return {
            "source": src_path,
            "destination": str(dest_dir),
            "carved_count": len(carved_items),
            "recovery_results": recovery_results
        }

