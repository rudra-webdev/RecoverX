"""
PhotoRec Integration Module for RecoverX
Provides controlled execution, version detection, output parsing, and license attribution
for CGSecurity's PhotoRec external data recovery tool.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
import shutil
import subprocess
import os

from utils.hashing import compute_sha256
from engine.file_validator import FileValidator
from utils.logging_config import logger
from config import PHOTOREC_PATH

class PhotoRecIntegration:
    LICENSE_INFO = {
        "name": "PhotoRec",
        "author": "Christophe GRENIER / CGSecurity",
        "license": "GNU General Public License v2+ (GPLv2+)",
        "website": "https://www.cgsecurity.org/wiki/PhotoRec",
        "description": "Signature-based file data recovery utility designed to carve lost files including video, documents, and archives from hard disks, CD-ROMs, and digital camera memory."
    }

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or self._detect_binary()

    def _detect_binary(self) -> Optional[str]:
        """Searches PATH and standard locations for photorec executable."""
        candidates = [
            PHOTOREC_PATH,
            shutil.which("photorec_win"),
            shutil.which("photorec_win.exe"),
            shutil.which("photorec"),
            shutil.which("photorec.exe"),
            r"C:\Program Files\testdisk\photorec_win.exe",
            r"C:\Program Files (x86)\testdisk\photorec_win.exe",
            r"C:\testdisk\photorec_win.exe"
        ]
        for c in candidates:
            if c and Path(c).is_file():
                return str(Path(c).resolve())
        return None

    def get_status(self) -> Dict[str, Any]:
        """Returns availability, version, and license information."""
        if not self.binary_path or not Path(self.binary_path).is_file():
            return {
                "is_available": False,
                "binary_path": None,
                "version": "Not Installed",
                "license_info": self.LICENSE_INFO,
                "installation_notice": (
                    "PhotoRec is an optional external carving backend. "
                    "RecoverX does NOT silently download binaries. "
                    "To enable, download TestDisk/PhotoRec from https://www.cgsecurity.org "
                    "and configure its path in Settings."
                )
            }

        try:
            res = subprocess.run(
                [self.binary_path, "/version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            raw_version = res.stdout.strip() or res.stderr.strip()
            first_line = raw_version.splitlines()[0] if raw_version else "PhotoRec (Version Unknown)"
            return {
                "is_available": True,
                "binary_path": self.binary_path,
                "version": first_line,
                "license_info": self.LICENSE_INFO
            }
        except Exception as e:
            return {
                "is_available": False,
                "binary_path": self.binary_path,
                "version": f"Detection error: {e}",
                "license_info": self.LICENSE_INFO
            }

    def run_carving(
        self,
        source_image: Path,
        output_dir: Path,
        timeout: int = 600,
        is_cancelled: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Executes PhotoRec in batch mode against a source disk image.
        Supports cooperative cancellation, timeout enforcement, and output parsing.
        """
        status = self.get_status()
        if not status["is_available"]:
            raise RuntimeError(
                f"PhotoRec is not installed or available: {status.get('installation_notice')}"
            )

        source = Path(source_image).resolve()
        if not source.is_file():
            raise FileNotFoundError(f"Source image not found: {source}")

        dest = Path(output_dir).resolve()
        dest.mkdir(parents=True, exist_ok=True)

        logger.info(f"Running PhotoRec on {source.name} -> {dest}")
        # Command syntax for batch mode: photorec_win.exe /cmd <image> search
        cmd = [self.binary_path, "/cmd", str(source), "search"]

        import time
        proc = subprocess.Popen(
            cmd,
            cwd=str(dest),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        start_time = time.time()
        cancelled = False
        while proc.poll() is None:
            if is_cancelled and is_cancelled():
                cancelled = True
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                logger.warning("PhotoRec carving cancelled cooperatively.")
                break

            if time.time() - start_time > timeout:
                proc.kill()
                raise TimeoutError(f"PhotoRec carving timed out after {timeout} seconds.")

            time.sleep(0.2)

        stdout, stderr = proc.communicate() if proc.poll() is not None else ("", "")

        # Parse recovered files from recup_dir.* subdirectories
        discovered = self.parse_recovered_output(dest)

        return {
            "source_image": str(source),
            "output_directory": str(dest),
            "photorec_version": status["version"],
            "total_recovered": len(discovered),
            "cancelled": cancelled,
            "returncode": proc.returncode,
            "stdout": stdout[:1000] if stdout else None,
            "stderr": stderr[:1000] if stderr else None,
            "files": discovered
        }

    def parse_recovered_output(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Parses PhotoRec output directories and validates recovered artifacts."""
        results = []
        target = Path(target_dir)

        for root, dirs, files in os.walk(target):
            root_path = Path(root)
            if "recup_dir" in root_path.name:
                for file_name in files:
                    file_path = root_path / file_name
                    try:
                        sz = file_path.stat().st_size
                        ext = file_path.suffix.lstrip(".").lower()
                        sha256 = compute_sha256(file_path)
                        val = FileValidator.validate(file_path, ext)
                        results.append({
                            "filename": file_name,
                            "path": str(file_path),
                            "extension": ext,
                            "category": val.get("category", "Other"),
                            "size_bytes": sz,
                            "sha256": sha256,
                            "is_valid": val.get("is_valid", False),
                            "confidence": val.get("confidence", 0.0),
                            "backend": "PhotoRec"
                        })
                    except Exception as e:
                        logger.warning(f"Error parsing PhotoRec artifact {file_name}: {e}")

        return results

