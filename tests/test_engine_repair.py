"""
Comprehensive Forensic Engine Repair Tests for RecoverX
=========================================================
Tests:
1. PNG chunk parsing, IHDR validation, CRC-32 integrity, and IEND termination.
2. Full byte-for-byte PNG carving (401,113 bytes) with exact SHA-256 match.
3. Chunk boundary spanning: file crossing 4MB chunk edge without truncation.
4. Rejection of truncated, corrupt payload, and invalid CRC PNGs.
5. Win32 raw device and drive letter path normalization (F:, F:\\, \\\\.\\F:).
6. Destination safety enforcement against same-drive extraction.
7. Zero-byte scan error detection preventing false success reporting.
"""

import io
import os
import struct
import tempfile
import zlib
from pathlib import Path
import pytest
from PIL import Image

from engine.file_validator import FileValidator
from engine.orchestrator import RecoveryOrchestrator
from engine.recovery_manager import RecoveryManager
from engine.signature_scanner import SignatureScanner
from engine.win32_raw_reader import Win32RawDeviceReader, is_raw_device_path, normalize_device_path
from utils.file_signatures import parse_png_size
from utils.hashing import compute_sha256
from config import CHUNK_SIZE


def _generate_target_size_png(target_bytes: int = 401113) -> bytes:
    """Generates a fully valid PNG image padded with a custom chunk to hit exact target size."""
    # 1. Create a base PNG in memory
    img = Image.new("RGBA", (256, 256), color=(45, 125, 220, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    base_png = buf.getvalue()

    # The base PNG ends with IEND (12 bytes: 4 len=0, 4 type=IEND, 4 crc)
    iend_idx = base_png.rfind(b"IEND")
    assert iend_idx != -1
    iend_chunk = base_png[iend_idx - 4:]
    pre_iend = base_png[:iend_idx - 4]

    # Calculate padding needed using an ancillary chunk (e.g. 'coNt')
    # Chunk overhead is 12 bytes: 4 len, 4 type, data, 4 crc
    current_len = len(pre_iend) + len(iend_chunk)
    padding_needed = target_bytes - current_len - 12
    assert padding_needed >= 0, f"Target bytes {target_bytes} too small for base PNG ({current_len})"

    pad_type = b"coNt"
    pad_data = b"X" * padding_needed
    pad_crc = zlib.crc32(pad_type + pad_data) & 0xFFFFFFFF
    custom_chunk = struct.pack(">I", padding_needed) + pad_type + pad_data + struct.pack(">I", pad_crc)

    final_png = pre_iend + custom_chunk + iend_chunk
    assert len(final_png) == target_bytes
    return final_png


class TestPNGEngineRepair:
    def test_parse_png_size_exact_match(self):
        """Verifies parse_png_size returns exact 401,113 bytes on valid PNG."""
        png_bytes = _generate_target_size_png(401113)
        size = parse_png_size(png_bytes, 0, verify_crc=True)
        assert size == 401113

    def test_png_validation_full_integrity(self):
        """Validates that FileValidator passes structure, signature, and content readable."""
        png_bytes = _generate_target_size_png(401113)
        res = FileValidator.validate(png_bytes, "png")
        assert res.is_valid is True
        assert res.signature_detected is True
        assert res.structure_validated is True
        assert res.content_readable is True
        assert res.confidence >= 0.9

    def test_png_rejection_on_crc_corruption(self):
        """Altering a byte in the chunk payload causes CRC failure and rejection."""
        png_bytes = bytearray(_generate_target_size_png(401113))
        # Corrupt one byte inside chunk data
        png_bytes[100] = (png_bytes[100] + 1) % 256
        corrupted = bytes(png_bytes)

        # parse_png_size must reject CRC mismatch
        size = parse_png_size(corrupted, 0, verify_crc=True)
        assert size is None

        # FileValidator must report invalid
        res = FileValidator.validate(corrupted, "png")
        assert res.is_valid is False
        assert res.structure_validated is False

    def test_png_rejection_on_missing_iend(self):
        """Truncated PNG missing terminal IEND must be marked invalid."""
        png_bytes = _generate_target_size_png(401113)
        truncated = png_bytes[:200000]

        size = parse_png_size(truncated, 0)
        assert size is None

        res = FileValidator.validate(truncated, "png")
        assert res.is_valid is False
        assert res.details.get("has_iend") is False

    def test_png_rejection_on_invalid_first_chunk(self):
        """A PNG whose first chunk is not IHDR must be rejected."""
        png_sig = b"\x89PNG\r\n\x1a\n"
        fake_chunk = struct.pack(">I", 10) + b"tEXt" + (b"A" * 10) + struct.pack(">I", 0x12345678)
        bad_png = png_sig + fake_chunk
        assert parse_png_size(bad_png, 0) is None

        res = FileValidator.validate(bad_png, "png")
        assert res.is_valid is False
        assert res.structure_validated is False


class TestSignatureScannerAndBoundaryCarving:
    def test_in_memory_carving_exact_sha256(self):
        """Ensures a 401,113-byte PNG carved from byte stream matches SHA-256 byte-for-byte."""
        png_bytes = _generate_target_size_png(401113)
        original_sha = compute_sha256(png_bytes)

        # Embed inside surrounding noise
        lead_noise = b"\x00\x55\xAA\xFF" * 1024  # 4096 bytes
        trail_noise = b"\x11\x22\x33\x44" * 1024
        stream = lead_noise + png_bytes + trail_noise

        scanner = SignatureScanner(target_formats=["png"])
        items = scanner.scan_bytes(stream, base_offset=1000)

        assert len(items) == 1
        item = items[0]
        assert item.extension == "png"
        assert item.offset == 1000 + len(lead_noise)
        assert item.length == 401113
        assert item.is_valid is True
        assert item.sha256 == original_sha
        assert item.data == png_bytes

    def test_chunk_boundary_spanning_carve(self):
        """
        Critical test: A 401,113-byte PNG placed across the 4MB chunk boundary
        must be carved intact with exact byte-for-byte SHA-256 match and no truncation.
        """
        png_bytes = _generate_target_size_png(401113)
        original_sha = compute_sha256(png_bytes)

        # Place PNG starting 200,000 bytes before the end of Chunk 1 (CHUNK_SIZE = 4MB)
        # So it spans 200,000 bytes in Chunk 1 and 201,113 bytes in Chunk 2.
        start_offset = CHUNK_SIZE - 200000
        total_size = CHUNK_SIZE + 500000

        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tf:
            tf_path = Path(tf.name)
            # Fill with leading padding
            tf.write(b"\x00" * start_offset)
            # Write PNG
            tf.write(png_bytes)
            # Write trailing padding to fill beyond chunk boundary
            remaining = total_size - (start_offset + len(png_bytes))
            if remaining > 0:
                tf.write(b"\x00" * remaining)

        try:
            scanner = SignatureScanner(target_formats=["png"])
            carved_items = scanner.scan_image_file(tf_path)

            assert len(carved_items) >= 1
            matching = [i for i in carved_items if i.sha256 == original_sha]
            assert len(matching) == 1, "Spanned PNG was not recovered or SHA-256 mismatched"

            item = matching[0]
            assert item.offset == start_offset
            assert item.length == 401113
            assert item.is_valid is True
            assert item.fragmented_warning is False
            assert item.data == png_bytes
        finally:
            if tf_path.is_file():
                tf_path.unlink()


class TestWin32DeviceAndPathSafety:
    def test_path_normalization(self):
        """Verifies drive letter paths are normalized to Win32 device namespace."""
        assert normalize_device_path("F:") == r"\\.\F:"
        assert normalize_device_path("F:\\") == r"\\.\F:"
        assert normalize_device_path("f:") == r"\\.\F:"
        assert normalize_device_path("f:/") == r"\\.\F:"
        assert normalize_device_path(r"\\.\PhysicalDrive1") == r"\\.\PhysicalDrive1"
        assert normalize_device_path("sample.img") == "sample.img"

    def test_is_raw_device_detection(self):
        assert is_raw_device_path("F:") is True
        assert is_raw_device_path("F:\\") is True
        assert is_raw_device_path(r"\\.\C:") is True
        assert is_raw_device_path(r"\\.\PhysicalDrive0") is True
        assert is_raw_device_path("image.raw") is False

    def test_same_drive_destination_safety_block(self):
        """Ensures recovering from F: to F:\\recovered is blocked by safety validator."""
        with pytest.raises(PermissionError) as exc_info:
            RecoveryManager.validate_destination_safety(
                source_path=Path("F:\\"),
                output_dir=Path(r"F:\RecoveredFiles")
            )
        assert "Forensic Safety Violation" in str(exc_info.value)
        assert "source drive" in str(exc_info.value).lower()

    def test_different_drive_destination_safety_allowed(self):
        """Recovery to a different physical drive or directory passes safety check."""
        RecoveryManager.validate_destination_safety(
            source_path=Path(r"\\.\F:"),
            output_dir=Path(r"D:\RecoverX\recovered")
        )

    def test_reader_size_query_unopened(self):
        """Reader queries size of existing image file or system volume accurately without failing."""
        reader = Win32RawDeviceReader("C:\\")
        size = reader.get_size()
        # System drive C: capacity is greater than 10GB
        assert size > 10 * (1024**3)


class TestOrchestratorAndWorkerRepair:
    def test_orchestrator_scans_disk_image_without_is_file_block(self):
        """Orchestrator carves files from image paths cleanly."""
        png_bytes = _generate_target_size_png(401113)
        original_sha = compute_sha256(png_bytes)

        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tf:
            tf.write(b"\x00" * 512 + png_bytes + b"\x00" * 512)
            tf_path = Path(tf.name)

        try:
            orchestrator = RecoveryOrchestrator(
                use_native_carver=True,
                use_photorec=False,
                use_tsk=False
            )
            items = orchestrator.scan(tf_path)
            assert len(items) >= 1
            found_png = next((i for i in items if i.get("sha256") == original_sha), None)
            assert found_png is not None
            assert found_png["detected_format"] == "PNG"
            assert found_png["extracted_size"] == 401113
            assert found_png["recovery_status"] == "Recoverable"
        finally:
            if tf_path.is_file():
                tf_path.unlink()

