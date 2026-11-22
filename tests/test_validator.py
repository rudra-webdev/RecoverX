"""
Test Suite for File Validator, Duplicate Detection, and Recovery Integrity.
"""
import pytest
from pathlib import Path
from engine.file_validator import FileValidator
from engine.recovery_manager import RecoveryManager
from engine.signature_scanner import CarvedItem
from utils.hashing import compute_sha256
from tests.test_signatures import (
    create_synthetic_png,
    create_synthetic_jpg,
    create_synthetic_gif,
    create_synthetic_webp,
    create_synthetic_pdf,
    create_synthetic_zip
)

def test_validator_valid_files():
    png = create_synthetic_png()
    res_png = FileValidator.validate(png, "png")
    assert res_png["is_valid"] is True
    assert res_png["confidence"] >= 0.8

    jpg = create_synthetic_jpg()
    res_jpg = FileValidator.validate(jpg, "jpg")
    assert res_jpg["is_valid"] is True

    gif = create_synthetic_gif()
    res_gif = FileValidator.validate(gif, "gif")
    assert res_gif["is_valid"] is True

    webp = create_synthetic_webp()
    res_webp = FileValidator.validate(webp, "webp")
    assert res_webp["is_valid"] is True

    pdf = create_synthetic_pdf()
    res_pdf = FileValidator.validate(pdf, "pdf")
    assert res_pdf["is_valid"] is True

    zip_bytes = create_synthetic_zip()
    res_zip = FileValidator.validate(zip_bytes, "zip")
    assert res_zip["is_valid"] is True

def test_validator_corrupt_files():
    # Truncated PNG
    corrupt_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    res = FileValidator.validate(corrupt_png, "png")
    assert res["is_valid"] is False

    # Corrupt JPG with no EOI
    corrupt_jpg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00" + (b"\xAA" * 50)
    res_jpg = FileValidator.validate(corrupt_jpg, "jpg")
    assert res_jpg["is_valid"] is False or res_jpg["confidence"] < 0.5

    # Corrupt ZIP
    corrupt_zip = b"PK\x03\x04\x14\x00\x00\x00truncated"
    res_zip = FileValidator.validate(corrupt_zip, "zip")
    assert res_zip["is_valid"] is False

def test_duplicate_detection_and_recovery_integrity(tmp_path: Path):
    source_img = tmp_path / "simulated_source.img"
    source_img.write_bytes(b"\x00" * 1024)

    output_dir = tmp_path / "recovered_test"
    mgr = RecoveryManager(output_dir=output_dir)

    png_data = create_synthetic_png()
    png_hash = compute_sha256(png_data)

    item1 = CarvedItem(
        offset=100,
        length=len(png_data),
        extension="png",
        data=png_data,
        sha256=png_hash,
        is_valid=True,
        confidence=1.0,
        details={},
        is_duplicate=False
    )

    # Identical item at a different offset (duplicate)
    item2 = CarvedItem(
        offset=5000,
        length=len(png_data),
        extension="png",
        data=png_data,
        sha256=png_hash,
        is_valid=True,
        confidence=1.0,
        details={},
        is_duplicate=True
    )

    results = mgr.recover_carved_items([item1, item2], source_path=source_img, skip_duplicates=True)

    assert results["total_recovered"] == 1
    assert results["skipped_duplicates"] == 1

    recovered_file = Path(results["files"][0]["path"])
    assert recovered_file.exists()
    assert compute_sha256(recovered_file) == png_hash

