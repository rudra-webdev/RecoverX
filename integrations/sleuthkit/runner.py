"""
The Sleuth Kit (TSK) Integration Module for RecoverX
Provides filesystem metadata inspection (NTFS, FAT, exFAT, ext4),
deleted directory entry discovery via fls, and file extraction via icat.
Distinguishes metadata records from confirmed content extraction.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
import shutil
import subprocess
import re
import os

from utils.hashing import compute_sha256
from engine.file_validator import FileValidator
from utils.file_signatures import get_file_category
from utils.logging_config import logger
from config import TSK_BIN_DIR

class TheSleuthKitIntegration:
    LICENSE_INFO = {
        "name": "The Sleuth Kit (TSK)",
        "author": "Brian Carrier / Basis Technology",
        "license": "Common Public License (CPL) / IBM Public License / GPLv2",
        "website": "https://www.sleuthkit.org/",
        "description": "Collection of command line tools and a C library that allows you to analyze disk images and recover files from them."
    }

    REQUIRED_TOOLS = ["fls", "fsstat", "icat", "mmls"]

    def __init__(self, bin_dir: Optional[str] = None):
        self.bin_dir = bin_dir or TSK_BIN_DIR or None
        self.tool_paths = self._detect_tools()

    def _detect_tools(self) -> Dict[str, Optional[str]]:
        """Finds paths for each required TSK utility."""
        found = {}
        for tool in self.REQUIRED_TOOLS:
            path = None
            if self.bin_dir:
                candidate = Path(self.bin_dir) / f"{tool}.exe"
                if candidate.is_file():
                    path = str(candidate)
            if not path:
                path = shutil.which(tool) or shutil.which(f"{tool}.exe")
            found[tool] = path
        return found

    def get_status(self) -> Dict[str, Any]:
        """Returns availability and version info for TSK tools."""
        fls_path = self.tool_paths.get("fls")
        if not fls_path or not Path(fls_path).is_file():
            return {
                "is_available": False,
                "version": "Not Installed",
                "tools": self.tool_paths,
                "license_info": self.LICENSE_INFO,
                "installation_notice": (
                    "The Sleuth Kit (TSK) is an optional external filesystem metadata backend. "
                    "RecoverX does NOT silently download binaries. "
                    "To enable, install TSK from https://www.sleuthkit.org and configure its path in Settings."
                )
            }

        try:
            res = subprocess.run([fls_path, "-V"], capture_output=True, text=True, timeout=5)
            version_str = res.stdout.strip() or res.stderr.strip()
            first_line = version_str.splitlines()[0] if version_str else "The Sleuth Kit (Version Unknown)"
            return {
                "is_available": True,
                "version": first_line,
                "tools": self.tool_paths,
                "license_info": self.LICENSE_INFO
            }
        except Exception as e:
            return {
                "is_available": False,
                "version": f"Detection error: {e}",
                "tools": self.tool_paths,
                "license_info": self.LICENSE_INFO
            }

    def analyze_filesystem_metadata(self, image_path: Path, offset: int = 0, fs_type: Optional[str] = None) -> Dict[str, Any]:
        """Runs fsstat to analyze filesystem layout and metadata."""
        fsstat = self.tool_paths.get("fsstat")
        if not fsstat:
            raise RuntimeError("fsstat is not available.")

        cmd = [fsstat]
        if fs_type:
            cmd.extend(["-f", fs_type.lower()])
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(str(image_path))

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            lines = res.stdout.splitlines()
            detected_fs = lines[0] if lines else "Unknown"
            return {
                "filesystem_type": detected_fs,
                "raw_output": lines[:30],
                "returncode": res.returncode,
                "stderr": res.stderr[:500] if res.stderr else None,
                "status": "success" if res.returncode == 0 else "error"
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def find_deleted_entries(
        self,
        image_path: Path,
        offset: int = 0,
        fs_type: Optional[str] = None,
        is_cancelled: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Runs fls to discover deleted directory and inode records across NTFS, FAT, and exFAT.
        Clearly marks them as METADATA_IDENTIFIED until extracted and validated.
        """
        fls = self.tool_paths.get("fls")
        if not fls:
            raise RuntimeError("fls is not available.")

        # fls -r (recursive) -p (display full path) -d (deleted entries only)
        cmd = [fls, "-r", "-p", "-d"]
        if fs_type:
            cmd.extend(["-f", fs_type.lower()])
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(str(image_path))

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode != 0 and res.stderr:
                logger.warning(f"TSK fls completed with non-zero code {res.returncode}: {res.stderr[:200]}")
            stdout = res.stdout
        except Exception as e:
            logger.error(f"Error running TSK fls: {e}")
            return []

        entries = []
        # Pattern: [r/d/v]/[r/d/v] * <inode>: <path>
        line_pattern = re.compile(r"^([a-z]+)/([a-z]+)\s+(\*?)\s*([0-9\-\:]+)\s*:\s*(.*)$")

        for line in stdout.splitlines():
            line = line.strip()
            m = line_pattern.match(line)
            if m:
                entry_type, alloc_type, is_del_marker, inode, orig_path = m.groups()
                is_deleted = (is_del_marker == "*")
                filename = os.path.basename(orig_path)
                ext = filename.split(".")[-1].lower() if "." in filename else ""

                entries.append({
                    "filename": filename,
                    "original_path": orig_path,
                    "inode": inode,
                    "extension": ext,
                    "category": get_file_category(ext),
                    "is_deleted_record": is_deleted,
                    "is_directory": entry_type.startswith("d"),
                    "status": "METADATA_RECORD_IDENTIFIED",
                    "recovery_method": "Filesystem Metadata (TSK fls)",
                    "content_extracted": False
                })

        return entries

    def extract_file_content(
        self,
        image_path: Path,
        inode: str,
        output_path: Path,
        offset: int = 0,
        fs_type: Optional[str] = None
    ) -> bool:
        """Extracts file content for a given inode using icat."""
        icat = self.tool_paths.get("icat")
        if not icat:
            raise RuntimeError("icat is not available.")

        cmd = [icat]
        if fs_type:
            cmd.extend(["-f", fs_type.lower()])
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.extend([str(image_path), inode])

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_path, "wb") as out_f:
                proc = subprocess.run(cmd, stdout=out_f, stderr=subprocess.PIPE, timeout=60)
            return proc.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0
        except Exception as e:
            logger.error(f"Failed to extract inode {inode} using icat: {e}")
            return False

