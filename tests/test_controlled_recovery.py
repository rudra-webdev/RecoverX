"""
Controlled Real-World Recovery Test Suite for RecoverX
======================================================
Labels:
- [Real-Media-Simulation]: Builds a genuine FAT-formatted filesystem disk image with VBR,
  FAT tables, Root Directory entries, and Data Clusters.
- [Controlled-Test]: Writes test files (PNG, PDF, TXT, JPG, Fragmented JPG), records original
  SHA-256 hashes, executes filesystem deletion (0xE5 marker + FAT cluster deallocation),
  carves unallocated and allocated space using the RecoverX recovery engine, extracts to an
  isolated destination, and performs cryptographic hash comparison.
"""

import io
import struct
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple
import pytest

from engine.signature_scanner import SignatureScanner
from engine.recovery_manager import RecoveryManager
from engine.file_validator import FileValidator
from engine.disk_imager import DiskImager
from engine.win32_raw_reader import Win32RawDeviceReader
from engine.drive_manager import DriveManager
from tests.test_signatures import (
    create_synthetic_png,
    create_synthetic_pdf,
    create_synthetic_jpg
)

def create_disposable_fat_image() -> Tuple[bytes, Dict[str, Dict[str, Any]]]:
    """
    Constructs a forensically authentic 2 MB FAT-formatted disk image in memory.
    Places known test files, then marks them deleted by:
    1. Overwriting first byte of directory entry with 0xE5 (standard FAT deleted marker).
    2. Zeroing FAT table allocation entries (marking clusters unallocated).
    Returns raw image bytes and ground-truth metadata of original files.
    """
    SECTOR_SIZE = 512
    TOTAL_SECTORS = 4096  # 2 MB image
    RESERVED_SECTORS = 1   # Sector 0 is VBR
    SECTORS_PER_FAT = 6
    NUM_FATS = 2
    ROOT_DIR_ENTRIES = 512
    ROOT_DIR_SECTORS = (ROOT_DIR_ENTRIES * 32) // SECTOR_SIZE  # 32 sectors
    FIRST_DATA_SECTOR = RESERVED_SECTORS + (NUM_FATS * SECTORS_PER_FAT) + ROOT_DIR_SECTORS

    image = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    # 1. Write Volume Boot Record (Sector 0)
    # JMP instruction, OEM name
    image[0:3] = b"\xEB\x3C\x90"
    image[3:11] = b"MSDOS5.0"
    # BIOS Parameter Block (BPB)
    struct.pack_into("<H", image, 11, SECTOR_SIZE)         # Bytes per sector: 512
    image[13] = 1                                           # Sectors per cluster: 1
    struct.pack_into("<H", image, 14, RESERVED_SECTORS)    # Reserved sectors: 1
    image[16] = NUM_FATS                                    # Number of FATs: 2
    struct.pack_into("<H", image, 17, ROOT_DIR_ENTRIES)    # Root directory entries: 512
    struct.pack_into("<H", image, 19, TOTAL_SECTORS)       # Total sectors: 4096
    image[21] = 0xF8                                        # Media descriptor: Fixed disk
    struct.pack_into("<H", image, 22, SECTORS_PER_FAT)     # Sectors per FAT: 6
    struct.pack_into("<H", image, 24, 32)                  # Sectors per track: 32
    struct.pack_into("<H", image, 26, 2)                   # Number of heads: 2
    # Boot signature at offset 510
    image[510:512] = b"\x55\xAA"

    # 2. Initialize FAT1 and FAT2 media headers
    fat1_offset = RESERVED_SECTORS * SECTOR_SIZE
    fat2_offset = (RESERVED_SECTORS + SECTORS_PER_FAT) * SECTOR_SIZE
    for offset in (fat1_offset, fat2_offset):
        image[offset:offset+3] = b"\xF8\xFF\xFF"  # Cluster 0 & 1 reserved

    # 3. Prepare ground-truth test files
    png_bytes = create_synthetic_png()
    pdf_bytes = create_synthetic_pdf()
    txt_bytes = "RecoverX Forensic Validation: The quick brown fox jumps over the lazy dog. 1234567890.\n".encode("utf-8")
    jpg_bytes = create_synthetic_jpg()
    # Partially overwritten/fragmented JPEG (SOI present, but payload truncated before EOI)
    frag_jpg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"\xAA" * 128)

    test_files = [
        ("TESTPNG.PNG", png_bytes, "png", True),
        ("DOCPDF.PDF", pdf_bytes, "pdf", True),
        ("NOTE.TXT", txt_bytes, "txt", True),
        ("PHOTO.JPG", jpg_bytes, "jpg", True),
        ("FRAG.JPG", frag_jpg_bytes, "jpg", False),  # Intentionally partial
    ]

    ground_truth: Dict[str, Dict[str, Any]] = {}
    root_dir_offset = (RESERVED_SECTORS + (NUM_FATS * SECTORS_PER_FAT)) * SECTOR_SIZE

    current_cluster = 2
    for entry_idx, (name, data, ext, is_fully_valid) in enumerate(test_files):
        file_sha256 = hashlib.sha256(data).hexdigest()
        cluster_offset = (FIRST_DATA_SECTOR + (current_cluster - 2)) * SECTOR_SIZE

        # Write file payload into data cluster
        image[cluster_offset : cluster_offset + len(data)] = data

        # Write 32-byte Directory Entry in Root Directory Table
        dir_entry_offset = root_dir_offset + (entry_idx * 32)
        base_name, file_ext = name.split(".")
        padded_name = f"{base_name:<8}{file_ext:<3}".encode("ascii")

        # In real deletion: first byte is marked 0xE5 (DELETED MARKER)
        deleted_name = b"\xE5" + padded_name[1:]
        image[dir_entry_offset : dir_entry_offset + 11] = deleted_name
        image[dir_entry_offset + 11] = 0x20  # Archive attribute
        struct.pack_into("<H", image, dir_entry_offset + 26, current_cluster)  # First cluster
        struct.pack_into("<I", image, dir_entry_offset + 28, len(data))          # File size

        # Note: Clusters in FAT are left unallocated (0x0000) to simulate deleted state
        ground_truth[name] = {
            "original_name": name,
            "extension": ext,
            "original_size": len(data),
            "original_sha256": file_sha256,
            "expected_valid": is_fully_valid,
            "sector_offset": cluster_offset,
            "original_bytes": data
        }

        # Advance cluster (allocating enough sectors per file size)
        sectors_needed = (len(data) + SECTOR_SIZE - 1) // SECTOR_SIZE
        current_cluster += max(1, sectors_needed)

    return bytes(image), ground_truth


# ==============================================================================
# Controlled Recovery Verification Tests
# ==============================================================================

def test_controlled_recovery_from_deleted_filesystem(tmp_path):
    """
    [Controlled-Test] Demonstrates genuine recovery of deleted files from a FAT image:
    1. Generates authentic FAT filesystem with deleted file entries (0xE5 marker).
    2. Scans using RecoverX SignatureScanner.
    3. Extracts and recovers files via RecoveryManager.
    4. Validates structural integrity and post-recovery SHA-256 hashes against original ground truth.
    5. Confirms honest reporting of valid vs fragmented/partial files.
    """
    image_bytes, ground_truth = create_disposable_fat_image()
    image_file = tmp_path / "disposable_fat.img"
    image_file.write_bytes(image_bytes)

    dest_dir = tmp_path / "recovered_output"
    dest_dir.mkdir(parents=True, exist_ok=True)

    # 1. Carve using actual RecoverX SignatureScanner
    scanner = SignatureScanner()
    carved_items = scanner.scan_image_file(image_file)

    assert len(carved_items) >= 3, f"Expected at least 3 recoverable artifacts, found {len(carved_items)}"

    # 2. Recover using actual RecoveryManager to separate output directory
    rec_manager = RecoveryManager(output_dir=dest_dir)
    results = rec_manager.recover_artifacts(
        artifacts=carved_items,
        source_path=image_file,
        skip_duplicates=False,
        only_valid=False
    )

    recovered_files = results["files"]
    assert len(recovered_files) > 0, "No files recovered by RecoveryManager"

    # 3. Compare recovered files against ground-truth originals
    recovered_by_hash = {f["sha256"]: f for f in recovered_files if f.get("sha256")}

    recovered_summary = {}
    for name, truth in ground_truth.items():
        orig_sha = truth["original_sha256"]
        matched_item = recovered_by_hash.get(orig_sha)

        if matched_item:
            recovered_summary[name] = {
                "status": "RECOVERED_100_HASH_MATCH",
                "original_sha256": orig_sha,
                "recovered_sha256": matched_item["sha256"],
                "is_valid": matched_item["is_valid"],
                "confidence": matched_item["confidence"]
            }
        else:
            # Check for partial/fragmented match by extension
            ext_matches = [f for f in recovered_files if f.get("extension") == truth["extension"]]
            recovered_summary[name] = {
                "status": "PARTIALLY_RECOVERED" if ext_matches else "NOT_RECOVERED",
                "original_sha256": orig_sha,
                "recovered_sha256": ext_matches[0]["sha256"] if ext_matches else None,
                "is_valid": ext_matches[0]["is_valid"] if ext_matches else False
            }

    # Verify PNG recovery
    png_result = recovered_summary.get("TESTPNG.PNG")
    assert png_result is not None
    assert png_result["status"] == "RECOVERED_100_HASH_MATCH"
    assert png_result["is_valid"] is True

    # Verify PDF recovery
    pdf_result = recovered_summary.get("DOCPDF.PDF")
    assert pdf_result is not None
    assert pdf_result["status"] == "RECOVERED_100_HASH_MATCH"
    assert pdf_result["is_valid"] is True

    # Verify JPEG recovery
    jpg_result = recovered_summary.get("PHOTO.JPG")
    assert jpg_result is not None
    assert jpg_result["status"] == "RECOVERED_100_HASH_MATCH"
    assert jpg_result["is_valid"] is True

    # Verify Fragmented file was NOT falsely declared 100% valid
    frag_result = recovered_summary.get("FRAG.JPG")
    assert frag_result is not None
    assert frag_result["status"] != "RECOVERED_100_HASH_MATCH"


def test_disk_imager_forensic_acquisition_and_verification(tmp_path):
    """
    [Real-Media-Simulation] Tests DiskImager:
    1. Creates disk image of source data.
    2. Enforces sector-aligned reading and destination safety.
    3. Verifies post-write bit-stream SHA-256 integrity match.
    4. Generates sidecar JSON metadata.
    """
    source_file = tmp_path / "source_device.img"
    # Create 64 KB test volume
    test_payload = (b"RecoverX Forensic Test Sector Payload\x00\xFF" * 16) * 100
    source_file.write_bytes(test_payload)

    output_image = tmp_path / "dest_evidence" / "acquired_evidence.raw"

    result = DiskImager.create_image(
        source_path=source_file,
        output_image_path=output_image,
        chunk_size=16384
    )

    assert result["status"] == "COMPLETED_VERIFIED"
    assert result["verified"] is True
    assert result["total_bytes"] == len(test_payload)
    assert Path(output_image).is_file()
    assert Path(output_image).stat().st_size == len(test_payload)

    # Confirm sidecar metadata file was written
    meta_path = output_image.with_suffix(output_image.suffix + ".metadata.json")
    assert meta_path.is_file()


def test_win32_raw_reader_file_mode(tmp_path):
    """
    [Unit] Tests Win32RawDeviceReader with image file.
    Verifies read, seek, tell, and get_size.
    """
    sample_file = tmp_path / "raw_sample.bin"
    sample_data = b"0123456789ABCDEF" * 64
    sample_file.write_bytes(sample_data)

    with Win32RawDeviceReader(sample_file) as reader:
        assert reader.get_size() == len(sample_data)
        assert reader.tell() == 0
        chunk1 = reader.read(16)
        assert chunk1 == sample_data[:16]
        assert reader.tell() == 16
        reader.seek(32)
        assert reader.tell() == 32
        chunk2 = reader.read(16)
        assert chunk2 == sample_data[32:48]


def test_physical_drive_enumeration_safety():
    """
    [Unit] Verifies DriveManager physical disk enumeration rules:
    - Primary physical drive (PhysicalDrive0) flagged as is_system_drive = True.
    - Requires confirmation = True.
    - Read only = True.
    - Flags requires_elevation honestly if running in non-admin environment.
    """
    phys_drives = DriveManager.list_physical_drives()
    if phys_drives:
        drive0 = phys_drives[0]
        assert drive0.is_system_drive is True
        assert drive0.requires_confirmation is True
        assert drive0.is_read_only is True
        assert drive0.source_type == "physical_drive"
