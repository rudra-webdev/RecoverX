"""
Additional Tests for Media Containers (MP4, AVI, MP3, WAV, DOCX) and Android Device Detection.
"""
import pytest
from pathlib import Path
from engine.file_validator import FileValidator
from engine.device_manager import DeviceManager
from utils.adb import ADBClient
from tests.test_signatures import (
    create_synthetic_mp4,
    create_synthetic_avi,
    create_synthetic_mp3,
    create_synthetic_wav,
    create_synthetic_zip
)

def test_media_container_validators():
    mp4 = create_synthetic_mp4()
    val_mp4 = FileValidator.validate(mp4, "mp4")
    assert val_mp4["is_valid"] is True

    avi = create_synthetic_avi()
    val_avi = FileValidator.validate(avi, "avi")
    assert val_avi["is_valid"] is True

    mp3 = create_synthetic_mp3()
    val_mp3 = FileValidator.validate(mp3, "mp3")
    assert val_mp3["is_valid"] is True

    wav = create_synthetic_wav()
    val_wav = FileValidator.validate(wav, "wav")
    assert val_wav["is_valid"] is True

def test_office_format_detection(tmp_path: Path):
    import zipfile
    import io

    # Create dummy docx
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<document/>")
    docx_bytes = buf.getvalue()

    res = FileValidator.validate(docx_bytes, "docx")
    assert res["is_valid"] is True
    assert res["type"] == "docx"

class MockADBClient:
    def list_devices(self):
        return [{
            "serial": "MOCK123456",
            "state": "device",
            "model": "Mi 11X Pro",
            "product": "haydn",
            "device": "haydn"
        }]

    def shell(self, serial: str, command: str, timeout: int = 30):
        if "getprop" in command:
            return (
                "[ro.product.manufacturer]: [Xiaomi]\n"
                "[ro.product.model]: [M2012K11I]\n"
                "[ro.product.marketname]: [Mi 11X Pro]\n"
                "[ro.product.device]: [haydn]\n"
                "[ro.build.version.release]: [14]\n"
                "[ro.build.version.sdk]: [34]\n"
                "[ro.build.version.security_patch]: [2024-05-01]\n"
                "[ro.build.display.id]: [UKQ1.231003.002]\n"
                "[ro.product.cpu.abi]: [arm64-v8a]\n"
                "[ro.boot.flash.locked]: [1]\n"
            )
        elif "getenforce" in command:
            return "Enforcing\n"
        elif "which su" in command:
            return "not found\n"
        elif "df" in command:
            return "/dev/fuse 230G 120G 110G 53% /storage/emulated/0\n"
        return ""

def test_mock_android_device_detection():
    mock_adb = MockADBClient()
    mgr = DeviceManager(adb_client=mock_adb)
    profile = mgr.inspect_device("MOCK123456")

    assert profile["status"] == "success"
    assert profile["manufacturer"] == "Xiaomi"
    assert profile["model"] == "M2012K11I"
    assert profile["android_version"] == "14"
    assert profile["sdk_version"] == "34"
    assert profile["root_status"] == "Non-Rooted (Secure)"
    assert profile["bootloader_status"] == "Locked"
    assert profile["selinux_mode"] == "Enforcing"

