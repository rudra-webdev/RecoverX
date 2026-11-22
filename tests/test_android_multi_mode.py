"""
RecoverX Phase 3 Test Suite: Android Multi-Mode Recovery Expansion
==================================================================
Labels:
- [Mocked-Android]: Automated tests with mocked Android target device (Xiaomi Android 14 / FBE / Non-Root).
- [Controlled-SD-Card]: Automated tests on synthetic/disposable FAT32 and exFAT disk images.
- [Unit]: Isolated safety, serial sanitization, and allowlist boundary validation tests.
"""

import io
import struct
import hashlib
from pathlib import Path
from typing import Dict, Any, List
import pytest

from utils.adb import ADBClient
from engine.device_manager import DeviceManager
from engine.android_scanner import AndroidScanner
from engine.sd_card_recovery import SDCardRecoveryManager
from engine.drive_manager import StorageSource
from engine.signature_scanner import SignatureScanner
from engine.recovery_manager import RecoveryManager
from tests.test_signatures import create_synthetic_png, create_synthetic_pdf


# ==============================================================================
# Mock Fixtures for Xiaomi Android 14 Target
# ==============================================================================

class MockXiaomiAndroid14ADB(ADBClient):
    """
    Mock ADB client simulating a Xiaomi 11X Pro / Poco F3 running official
    Xiaomi HyperOS on Android 14 with File-Based Encryption (FBE) and Scoped Storage.
    """
    def __init__(self, is_rooted: bool = False):
        super().__init__(dry_run=False)
        self.is_rooted = is_rooted
        self.pull_calls = []

    def list_devices(self) -> List[Dict[str, str]]:
        return [{
            "serial": "M2012K11I_XIAOMI_14",
            "state": "device",
            "model": "Mi 11X Pro",
            "product": "haydn_in",
            "device": "haydn"
        }]

    def shell(self, serial: str, command: str, timeout: int = 30) -> str:
        self.validate_serial(serial)
        if "getprop" in command:
            return (
                "[ro.product.manufacturer]: [Xiaomi]\n"
                "[ro.product.brand]: [Xiaomi]\n"
                "[ro.product.model]: [M2012K11I]\n"
                "[ro.product.marketname]: [Xiaomi 11X Pro 5G]\n"
                "[ro.product.device]: [haydn]\n"
                "[ro.build.version.release]: [14]\n"
                "[ro.build.version.sdk]: [34]\n"
                "[ro.build.version.security_patch]: [2024-06-01]\n"
                "[ro.build.display.id]: [UKQ1.231003.002.OS1.0.5.0.UKKINXM]\n"
                "[ro.mi.os.version.name]: [OS1.0.5.0.UKKINXM]\n"
                "[ro.product.cpu.abi]: [arm64-v8a]\n"
                "[ro.crypto.type]: [file]\n"
                "[ro.crypto.state]: [encrypted]\n"
                "[ro.boot.flash.locked]: [1]\n"
            )
        elif "getenforce" in command:
            return "Enforcing\n"
        elif "which su" in command:
            return "/system/xbin/su\n" if self.is_rooted else "not found\n"
        elif "df" in command:
            return (
                "Filesystem     Size  Used Avail Use% Mounted on\n"
                "/dev/fuse      228G  114G  114G  50% /storage/emulated/0\n"
                "/dev/block/vold/public:179,1 59G 12G 47G 21% /storage/ABCD-1234\n"
            )
        elif "find" in command and "head" in command:
            return (
                "/storage/emulated/0/DCIM/Camera/IMG_20240601_001.jpg\n"
                "/storage/emulated/0/Pictures/Screenshots/Screenshot_01.png\n"
                "/storage/emulated/0/Download/Statement.pdf\n"
                "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt14\n"
            )
        elif "/data/data/com.whatsapp" in command:
            return "ls: /data/data/com.whatsapp: Permission denied\n"
        elif "ls -d" in command:
            return "/storage/emulated/0\n"
        return ""

    def pull_file(self, serial: str, remote_path: str, local_destination: str, timeout: int = 120) -> bool:
        self.validate_serial(serial)
        self.pull_calls.append((remote_path, local_destination))
        dest = Path(local_destination)
        dest.parent.mkdir(parents=True, exist_ok=True)

        # Write genuine synthetic format bytes based on extension
        ext = dest.suffix.lower().lstrip(".")
        if ext == "png":
            dest.write_bytes(create_synthetic_png())
        elif ext == "pdf":
            dest.write_bytes(create_synthetic_pdf())
        else:
            dest.write_bytes(b"RecoverX Simulated Android Pulled Content\n")
        return True


# ==============================================================================
# 1. MODE A: Logical Shared-Storage Investigation Tests
# ==============================================================================

def test_mode_a_logical_profiling_and_fbe_detection():
    """
    [Mocked-Android] Tests Mode A device profiling on modern Xiaomi Android 14:
    - Identifies manufacturer, model, market name, codename.
    - Confirms Android 14 (API 34) and HyperOS flavor.
    - Detects File-Based Encryption (FBE) active with hardware keys.
    - Identifies Scoped Storage policy.
    - Confirms SELinux is Enforcing and Bootloader is Locked.
    """
    mock_adb = MockXiaomiAndroid14ADB(is_rooted=False)
    mgr = DeviceManager(adb_client=mock_adb)
    profile = mgr.inspect_device("M2012K11I_XIAOMI_14")

    assert profile["status"] == "success"
    assert profile["manufacturer"] == "Xiaomi"
    assert profile["android_version"] == "14"
    assert profile["sdk_version"] == "34"
    assert "HyperOS" in profile["os_flavor"]
    assert profile["fbe_active"] is True
    assert "File-Based Encryption" in profile["fbe_status"]
    assert profile["scoped_storage_active"] is True
    assert profile["root_status"] == "Non-Rooted (Secure)"
    assert profile["bootloader_status"] == "Locked"
    assert profile["selinux_mode"] == "Enforcing"
    assert profile["removable_sd_card_mount"] == "/storage/ABCD-1234"


def test_mode_a_accessible_directory_enumeration():
    """
    [Mocked-Android] Tests enumeration of accessible shared-storage files:
    - Scans DCIM, Pictures, Downloads, and WhatsApp shared media.
    - Populates path, filename, extension, and forensic category.
    """
    mock_adb = MockXiaomiAndroid14ADB()
    scanner = AndroidScanner(adb_client=mock_adb)
    files = scanner.enumerate_accessible_files("M2012K11I_XIAOMI_14", max_files=10)

    assert len(files) == 4
    filenames = [f["filename"] for f in files]
    assert "IMG_20240601_001.jpg" in filenames
    assert "Screenshot_01.png" in filenames
    assert "Statement.pdf" in filenames
    assert "msgstore.db.crypt14" in filenames


def test_mode_a_copy_accessible_files_with_sha256_and_validation(tmp_path):
    """
    [Mocked-Android] Tests pulling accessible files to local investigation directory:
    - Verifies adb pull execution.
    - Computes post-copy SHA-256 hash.
    - Performs FileValidator structural validation (5 distinguished states).
    - Checks VERIFIED_COPIED status.
    """
    mock_adb = MockXiaomiAndroid14ADB()
    scanner = AndroidScanner(adb_client=mock_adb)
    dest_dir = tmp_path / "investigation_evidence"

    remote_files = [
        "/storage/emulated/0/Pictures/Screenshots/Screenshot_01.png",
        "/storage/emulated/0/Download/Statement.pdf"
    ]

    res = scanner.copy_accessible_files(
        serial="M2012K11I_XIAOMI_14",
        remote_paths=remote_files,
        destination_dir=dest_dir
    )

    assert res["status"] == "success"
    assert res["total_copied"] == 2
    assert res["verified_valid"] == 2

    for f in res["files"]:
        assert f["status"] == "VERIFIED_COPIED"
        assert f["is_valid"] is True
        assert f["structure_validated"] is True
        assert f["content_readable"] is True
        assert f["recovery_completed"] is True
        assert f["hash_verified"] is True
        assert Path(f["local_path"]).is_file()


def test_mode_a_honest_private_sandbox_boundary():
    """
    [Mocked-Android] Verifies that private sandbox /data/data/com.whatsapp is recognized
    as inaccessible without root, and no false recovery claims are made.
    """
    mock_adb = MockXiaomiAndroid14ADB(is_rooted=False)
    scanner = AndroidScanner(adb_client=mock_adb)
    sec_checks = scanner._verify_security_restrictions("M2012K11I_XIAOMI_14")

    whatsapp_sandbox = sec_checks.get("/data/data/com.whatsapp")
    assert whatsapp_sandbox is not None
    assert whatsapp_sandbox["accessible"] is False
    assert "Permission denied" in whatsapp_sandbox["response"]


# ==============================================================================
# 2. MODE B: SD Card Recovery via Card Reader Tests
# ==============================================================================

def test_mode_b_sd_card_detection_filtering():
    """
    [Controlled-SD-Card] Verifies that SDCardRecoveryManager identifies removable media
    while excluding non-removable fixed system storage.
    """
    sd_cards = SDCardRecoveryManager.detect_sd_cards()
    # Ensure no system drive (C:) is ever misidentified as an SD card
    for card in sd_cards:
        assert card.is_system_drive is False
        assert card.is_read_only is True


def test_mode_b_exfat_image_carving(tmp_path):
    """
    [Controlled-SD-Card] Tests carving on an exFAT formatted storage image:
    1. Creates 1 MB disk image with exFAT VBR header (b"EXFAT   ").
    2. Writes synthetic valid PNG and PDF files into sectors.
    3. Executes read-only signature carving via SignatureScanner and RecoveryManager.
    4. Verifies byte-for-byte SHA-256 match.
    """
    SECTOR_SIZE = 512
    TOTAL_SECTORS = 2048  # 1 MB image
    image = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    # 1. Write exFAT VBR (Sector 0)
    image[0:3] = b"\xEB\x76\x90"
    image[3:11] = b"EXFAT   "  # 8 bytes exFAT OEM name
    struct.pack_into("<H", image, 510, 0xAA55)  # Boot signature

    # 2. Write embedded PNG and PDF files into clusters
    png_data = create_synthetic_png()
    pdf_data = create_synthetic_pdf()
    png_sha = hashlib.sha256(png_data).hexdigest()
    pdf_sha = hashlib.sha256(pdf_data).hexdigest()

    # Offset 64 KB (Sector 128)
    png_offset = 128 * SECTOR_SIZE
    image[png_offset : png_offset + len(png_data)] = png_data

    # Offset 128 KB (Sector 256)
    pdf_offset = 256 * SECTOR_SIZE
    image[pdf_offset : pdf_offset + len(pdf_data)] = pdf_data

    exfat_img = tmp_path / "sdcard_exfat.raw"
    exfat_img.write_bytes(image)

    dest_dir = tmp_path / "recovered_sd_evidence"
    dest_dir.mkdir(parents=True, exist_ok=True)

    # 3. Carve and recover
    scanner = SignatureScanner()
    carved = scanner.scan_image_file(exfat_img)
    assert len(carved) >= 2

    rec_mgr = RecoveryManager(output_dir=dest_dir)
    res = rec_mgr.recover_artifacts(carved, source_path=exfat_img)

    recovered_hashes = {f["sha256"]: f for f in res["files"]}
    assert png_sha in recovered_hashes
    assert pdf_sha in recovered_hashes
    assert recovered_hashes[png_sha]["is_valid"] is True
    assert recovered_hashes[pdf_sha]["is_valid"] is True


# ==============================================================================
# 3. MODE C: Advanced Root & Architecture Profile Tests
# ==============================================================================

def test_mode_c_advanced_root_and_security_reporting():
    """
    [Mocked-Android] Verifies that existing root binaries are detected safely
    without executing su or attempting privilege escalation.
    """
    rooted_adb = MockXiaomiAndroid14ADB(is_rooted=True)
    mgr = DeviceManager(adb_client=rooted_adb)
    prof = mgr.inspect_device("M2012K11I_XIAOMI_14")

    assert prof["is_rooted"] is True
    assert prof["root_status"] == "Root Binary Present"

    # Confirm non-destructive limitation note is present
    limitations = " ".join(prof["forensic_limitations"])
    assert "non-destructive" in limitations.lower()


# ==============================================================================
# 4. Security & Argument Sanitization Tests
# ==============================================================================

def test_adb_serial_validation_metacharacters_rejected():
    """
    [Unit] Verifies ADBClient.validate_serial rejects command injection payloads.
    """
    client = ADBClient(dry_run=True)

    with pytest.raises(PermissionError):
        client.validate_serial("device; rm -rf /")

    with pytest.raises(PermissionError):
        client.validate_serial("phone$(calc)")

    with pytest.raises(PermissionError):
        client.validate_serial("phone`whoami`")

    # Valid serials must pass
    assert client.validate_serial("M2012K11I_XIAOMI_14") == "M2012K11I_XIAOMI_14"
    assert client.validate_serial("192.168.1.100:5555") == "192.168.1.100:5555"


def test_adb_pull_metacharacters_rejected(tmp_path):
    """
    [Unit] Verifies ADBClient.pull_file rejects remote path metacharacters.
    """
    client = ADBClient(dry_run=True)
    local_dest = str(tmp_path / "test.png")

    with pytest.raises(PermissionError):
        client.pull_file("valid_serial", "/sdcard/photo.jpg; rm -rf /", local_dest)

    with pytest.raises(PermissionError):
        client.pull_file("valid_serial", "/sdcard/photo$(calc).jpg", local_dest)


def test_cooperative_cancellation_during_extraction(tmp_path):
    """
    [Unit] Verifies that copy_accessible_files terminates immediately when cancelled.
    """
    mock_adb = MockXiaomiAndroid14ADB()
    scanner = AndroidScanner(adb_client=mock_adb)
    dest_dir = tmp_path / "cancelled_dest"

    remote_files = [
        f"/storage/emulated/0/DCIM/Photo_{i}.png" for i in range(10)
    ]

    call_count = 0
    def cancel_after_one():
        nonlocal call_count
        call_count += 1
        return call_count > 1

    res = scanner.copy_accessible_files(
        serial="M2012K11I_XIAOMI_14",
        remote_paths=remote_files,
        destination_dir=dest_dir,
        is_cancelled=cancel_after_one
    )

    # Should have stopped after 1 or 2 items
    assert res["total_copied"] <= 2

