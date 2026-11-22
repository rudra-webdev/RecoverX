"""
RecoverX Configuration Module
Defines default paths, forensic safety settings, signatures, and environment defaults.
Supports local persistent settings via recoverx_config.json.
"""
from pathlib import Path
import os
import shutil
import json

# Base directories
BASE_DIR = Path(__file__).resolve().parent
RECOVERED_DIR = BASE_DIR / "recovered"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure output directories exist
RECOVERED_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_FILE = REPORTS_DIR / "recoverx_config.json"

def load_user_settings() -> dict:
    """Loads persisted user settings from recoverx_config.json."""
    if CONFIG_FILE.is_file():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_user_settings(settings: dict) -> bool:
    """Saves user settings to recoverx_config.json."""
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        current = load_user_settings()
        current.update(settings)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
        return True
    except Exception:
        return False

# Load persistent settings if available
_user_cfg = load_user_settings()

# Forensic safety settings
SAFETY_WRITE_BLOCK = True  # Strict prohibition of writes to target/source
STRICT_READ_ONLY = True
OFFLINE_MODE = True  # Mandatory offline mode: all outbound network I/O blocked
DRY_RUN = bool(_user_cfg.get("dry_run_default", False))  # Dry-run mode
ENFORCE_ADB_ALLOWLIST = True  # Strict ADB command allowlist enforcement
MAX_CARVE_FILE_SIZE = 500 * 1024 * 1024  # 500 MB max per carved file
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB read chunk size for binary carving
OVERLAP_SIZE = 64 * 1024  # 64 KB overlap across chunk boundaries

# ADB Path resolution
COMMON_ADB_PATHS = [
    os.environ.get("RECOVERX_ADB_PATH", ""),
    os.environ.get("ADB_PATH", ""),
    str(Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe"),
    r"C:\platform-tools\adb.exe",
    r"C:\Program Files\Android\platform-tools\adb.exe",
]

def resolve_adb_path() -> str:
    """Finds the usable adb executable path on the host system."""
    for path_str in COMMON_ADB_PATHS:
        if path_str and Path(path_str).is_file():
            return path_str
    system_adb = shutil.which("adb")
    if system_adb:
        return system_adb
    return str(Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe")

ADB_PATH = resolve_adb_path()

# Optional external tools
PHOTOREC_PATH = _user_cfg.get("photorec_path") or shutil.which("photorec_win") or shutil.which("photorec") or ""
TSK_BIN_DIR = _user_cfg.get("tsk_bin_dir") or ""
FFMPEG_PATH = shutil.which("ffmpeg") or ""
FFPROBE_PATH = shutil.which("ffprobe") or ""

if _user_cfg.get("recovered_dir"):
    try:
        custom_rec = Path(_user_cfg["recovered_dir"])
        custom_rec.mkdir(parents=True, exist_ok=True)
        RECOVERED_DIR = custom_rec
    except Exception:
        pass

if _user_cfg.get("reports_dir"):
    try:
        custom_rep = Path(_user_cfg["reports_dir"])
        custom_rep.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR = custom_rep
    except Exception:
        pass

# Application metadata
APP_NAME = "RecoverX"
APP_VERSION = "2.1.0"
APP_DESCRIPTION = "Windows-first Digital Forensics & Multi-Engine Data Recovery Platform"
APP_AUTHOR = "RecoverX Digital Forensics Team"

# Supported Carving Formats (22+ formats)
SUPPORTED_FORMATS = [
    "jpg",
    "png",
    "gif",
    "webp",
    "bmp",
    "tiff",
    "heic",
    "mp4",
    "mov",
    "avi",
    "mkv",
    "mp3",
    "wav",
    "m4a",
    "pdf",
    "docx",
    "xlsx",
    "pptx",
    "txt",
    "zip",
    "rar",
    "7z",
    "db",
    "crypt14",
    "crypt15",
]
