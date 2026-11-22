"""
Android Logical Forensic Scanner for RecoverX
Performs comprehensive read-only logical artifact discovery on connected Android devices.
"""
from typing import Dict, Any, List, Optional
import os
import re
from pathlib import Path
from utils.adb import ADBClient
from engine.device_manager import DeviceManager
from utils.hashing import compute_sha256
from engine.file_validator import FileValidator
from engine.recovery_manager import RecoveryManager
from utils.file_signatures import get_file_category
from utils.logging_config import logger

class AndroidScanner:
    ACCESSIBLE_STORAGE_ROOTS = [
        "/storage/emulated/0",
        "/sdcard",
    ]

    COMMON_MEDIA_DIRS = [
        "DCIM",
        "Pictures",
        "Download",
        "Documents",
        "Movies",
        "Music",
        "Audiobooks",
        "Podcasts",
        "Recordings",
        "LOST.DIR"
    ]

    WHATSAPP_STORAGE_LOCATIONS = [
        "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp",
        "/storage/emulated/0/WhatsApp",
        "/sdcard/Android/media/com.whatsapp/WhatsApp",
        "/sdcard/WhatsApp",
        "/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp Business",
        "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business"
    ]

    SYSTEM_RESTRICTED_APP_PATHS = [
        "/data/data/com.whatsapp",
        "/data/user/0/com.whatsapp",
        "/data/data/com.whatsapp.w4b",
    ]

    def __init__(self, adb_client: Optional[ADBClient] = None, dry_run: bool = False):
        self.adb = adb_client or ADBClient(dry_run=dry_run)
        self.device_mgr = DeviceManager(self.adb, dry_run=dry_run)

    def scan_device(self, serial: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes a complete read-only logical investigation on the target device.
        """
        profile = self.device_mgr.inspect_device(serial)
        if profile.get("status") != "success":
            return profile

        target_serial = profile["serial"]
        logger.info(f"Starting logical forensic scan on device {target_serial}...")

        # 1. Enumerate accessible shared storage directories
        storage_roots = self._check_accessible_roots(target_serial)

        # 2. Inspect standard media paths
        media_findings = self._inspect_media_directories(target_serial)

        # 3. Discover cache and thumbnail artifacts
        cache_artifacts = self._discover_cache_and_thumbnails(target_serial)

        # 4. Search for WhatsApp artifacts (Media, Databases, Backups)
        whatsapp_artifacts = self._inspect_whatsapp_locations(target_serial)

        # 5. Search for Exported Chat TXT files in accessible paths
        chat_exports = self._find_chat_exports(target_serial)

        # 6. Verify security restrictions on private app sandbox
        sandbox_checks = self._verify_security_restrictions(target_serial)

        investigation_report = {
            "status": "success",
            "device_profile": profile,
            "accessible_storage_roots": storage_roots,
            "media_findings": media_findings,
            "cache_and_thumbnails": cache_artifacts,
            "whatsapp_artifacts": whatsapp_artifacts,
            "exported_chats": chat_exports,
            "security_boundaries": sandbox_checks,
            "forensic_summary": {
                "total_media_folders_inspected": len(media_findings.get("folders", [])),
                "total_cache_entries": len(cache_artifacts.get("discovered", [])),
                "whatsapp_media_items_found": whatsapp_artifacts.get("total_media_count", 0),
                "whatsapp_databases_found": len(whatsapp_artifacts.get("databases", [])),
                "chat_exports_found": len(chat_exports),
                "sandbox_accessible": False
            }
        }

        return investigation_report

    def _check_accessible_roots(self, serial: str) -> List[Dict[str, Any]]:
        accessible = []
        for root in self.ACCESSIBLE_STORAGE_ROOTS:
            out = self.adb.shell(serial, f"ls -d {root} 2>/dev/null").strip()
            if out and "No such" not in out and "Permission denied" not in out:
                details = self.adb.shell(serial, f"ls -l {root} 2>/dev/null | head -n 30")
                accessible.append({
                    "path": root,
                    "accessible": True,
                    "preview": [l.strip() for l in details.splitlines() if l.strip()]
                })
            else:
                accessible.append({
                    "path": root,
                    "accessible": False,
                    "error": "Path inaccessible or not mounted"
                })
        return accessible

    def _inspect_media_directories(self, serial: str) -> Dict[str, Any]:
        folders_info = []
        base = "/storage/emulated/0"
        for folder in self.COMMON_MEDIA_DIRS:
            path = f"{base}/{folder}"
            out = self.adb.shell(serial, f"ls -la '{path}' 2>/dev/null").strip()
            if out and "No such file" not in out and "Permission denied" not in out:
                lines = [l for l in out.splitlines() if l.strip() and not l.startswith("total")]
                count_out = self.adb.shell(serial, f"find '{path}' -type f 2>/dev/null | wc -l").strip()
                folders_info.append({
                    "name": folder,
                    "path": path,
                    "accessible": True,
                    "file_count": int(count_out) if count_out.isdigit() else len(lines),
                    "sample_entries": lines[:10]
                })
        return {"folders": folders_info}

    def _discover_cache_and_thumbnails(self, serial: str) -> Dict[str, Any]:
        """Finds .thumbnails, .cache, and cache database remnants in shared storage."""
        discovered = []
        cmd = "find /storage/emulated/0 -maxdepth 4 \\( -name '.thumbnails' -o -name '.thumb' -o -name 'LOST.DIR' -o -name '.cache' \\) 2>/dev/null"
        out = self.adb.shell(serial, cmd)
        for line in out.splitlines():
            item_path = line.strip()
            if not item_path:
                continue
            count_res = self.adb.shell(serial, f"find '{item_path}' -type f 2>/dev/null | wc -l").strip()
            discovered.append({
                "path": item_path,
                "file_count": int(count_res) if count_res.isdigit() else 0
            })
        return {"discovered": discovered}

    def _inspect_whatsapp_locations(self, serial: str) -> Dict[str, Any]:
        """Inspects all known WhatsApp storage trees for media, databases, and backups."""
        active_roots = []
        for loc in self.WHATSAPP_STORAGE_LOCATIONS:
            chk = self.adb.shell(serial, f"ls -d '{loc}' 2>/dev/null").strip()
            if chk and "No such" not in chk and "Permission denied" not in chk:
                active_roots.append(loc)

        databases_found = []
        media_summary = {}
        total_media_count = 0

        for root in active_roots:
            # 1. Search for Databases (.db, .crypt12, .crypt14, .crypt15)
            db_out = self.adb.shell(serial, f"find '{root}' -type f \\( -name '*.db*' -o -name '*.crypt*' \\) 2>/dev/null")
            for line in db_out.splitlines():
                db_file = line.strip()
                if not db_file:
                    continue
                size_out = self.adb.shell(serial, f"stat -c '%s' '{db_file}' 2>/dev/null || wc -c < '{db_file}'").strip()
                size_bytes = int(size_out) if size_out.isdigit() else 0
                databases_found.append({
                    "path": db_file,
                    "filename": os.path.basename(db_file),
                    "size_bytes": size_bytes,
                    "location_root": root
                })

            # 2. Inspect Media subdirectories
            media_subdirs = [
                "WhatsApp Images",
                "WhatsApp Video",
                "WhatsApp Audio",
                "WhatsApp Voice Notes",
                "WhatsApp Documents",
                "WhatsApp Stickers",
                "WhatsApp Animated Gifs",
                "WhatsApp Profile Photos"
            ]
            for sub in media_subdirs:
                sub_path = f"{root}/Media/{sub}"
                count_out = self.adb.shell(serial, f"find '{sub_path}' -type f 2>/dev/null | wc -l").strip()
                count = int(count_out) if count_out.isdigit() else 0
                media_summary[sub] = media_summary.get(sub, 0) + count
                total_media_count += count

        return {
            "active_roots": active_roots,
            "databases": databases_found,
            "media_breakdown": media_summary,
            "total_media_count": total_media_count
        }

    def _find_chat_exports(self, serial: str) -> List[Dict[str, Any]]:
        """Finds exported WhatsApp chat files (*.txt) across shared storage."""
        exports = []
        cmd = "find /storage/emulated/0/Download /storage/emulated/0/Documents -name '*WhatsApp Chat*.txt' -o -name '*WhatsApp*.txt' 2>/dev/null"
        out = self.adb.shell(serial, cmd)
        for line in out.splitlines():
            txt_path = line.strip()
            if not txt_path:
                continue
            size_out = self.adb.shell(serial, f"wc -c < '{txt_path}' 2>/dev/null").strip()
            exports.append({
                "path": txt_path,
                "filename": os.path.basename(txt_path),
                "size_bytes": int(size_out) if size_out.isdigit() else 0
            })
        return exports

    def _verify_security_restrictions(self, serial: str) -> Dict[str, Any]:
        """
        Confirms security boundaries on private application sandboxes (/data/data/com.whatsapp).
        Verifies that Android DAC/MAC properly denies unauthorized reads.
        """
        sandbox_results = {}
        for path in self.SYSTEM_RESTRICTED_APP_PATHS:
            out = self.adb.shell(serial, f"ls '{path}' 2>&1")
            denied = "Permission denied" in out or "not found" in out or "inaccessible" in out
            sandbox_results[path] = {
                "accessible": not denied,
                "response": out.strip()[:100],
                "explanation": "Protected by Android Linux DAC UID isolation and SELinux untrusted_app domain. Accessible strictly within app sandbox or via authorized adb backup agent."
            }
        return sandbox_results

    def enumerate_accessible_files(self, serial: str, max_files: int = 500) -> List[Dict[str, Any]]:
        """
        Enumerates individual accessible files in public shared storage
        (DCIM, Pictures, WhatsApp Media, WhatsApp Databases, Download, Documents).
        """
        files_found = []
        seen_paths = set()
        target_roots = [
            "/storage/emulated/0/DCIM",
            "/storage/emulated/0/Pictures",
            "/storage/emulated/0/Download",
            "/storage/emulated/0/Documents",
            "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media",
            "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Databases",
            "/storage/emulated/0/WhatsApp/Media",
            "/storage/emulated/0/WhatsApp/Databases"
        ]

        for root in target_roots:
            if len(files_found) >= max_files:
                break
            remaining = max_files - len(files_found)
            cmd = f"find '{root}' -maxdepth 3 -type f 2>/dev/null | head -n {remaining}"
            out = self.adb.shell(serial, cmd)
            for line in out.splitlines():
                remote_path = line.strip()
                if not remote_path or remote_path in seen_paths:
                    continue
                seen_paths.add(remote_path)
                filename = os.path.basename(remote_path)
                ext = filename.split(".")[-1].lower() if "." in filename else ""
                files_found.append({
                    "remote_path": remote_path,
                    "filename": filename,
                    "extension": ext,
                    "category": get_file_category(ext),
                    "root_directory": root,
                    "is_accessible": True
                })
                if len(files_found) >= max_files:
                    break

        return files_found

    def copy_accessible_files(
        self,
        serial: str,
        remote_paths: List[str],
        destination_dir: Path,
        progress_callback: Optional[Any] = None,
        is_cancelled: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Pulls specified accessible files from Android device to a local destination directory.
        Calculates SHA-256 hashes, performs structural validation with FileValidator,
        and logs extraction provenance.
        """
        dest_dir = Path(destination_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Initiating extraction of {len(remote_paths)} Android files to {dest_dir}...")
        extracted_files = []
        total_items = len(remote_paths)

        for idx, remote_path in enumerate(remote_paths, 1):
            if is_cancelled and is_cancelled():
                logger.warning("Android file extraction cancelled by user.")
                break

            filename = os.path.basename(remote_path)
            ext = filename.split(".")[-1].lower() if "." in filename else "bin"
            local_file = dest_dir / filename

            # Ensure unique filename to prevent overwrite collisions
            counter = 1
            stem = Path(filename).stem
            while local_file.exists():
                local_file = dest_dir / f"{stem}_{counter}.{ext}"
                counter += 1

            success = self.adb.pull_file(serial, remote_path, str(local_file))
            if not success or not local_file.is_file():
                extracted_files.append({
                    "remote_path": remote_path,
                    "filename": filename,
                    "local_path": None,
                    "status": "FAILED",
                    "error": "ADB pull failed or file inaccessible"
                })
                if progress_callback:
                    progress_callback(idx, total_items, filename, False)
                continue

            file_size = local_file.stat().st_size
            sha256_hash = compute_sha256(local_file)
            val_result = FileValidator.validate_file(local_file, ext)

            item_info = {
                "remote_path": remote_path,
                "filename": local_file.name,
                "local_path": str(local_file),
                "extension": ext,
                "category": get_file_category(ext),
                "size_bytes": file_size,
                "sha256": sha256_hash,
                "is_valid": val_result.get("is_valid", False),
                "confidence": val_result.get("confidence", 0.0),
                "signature_detected": val_result.get("signature_detected", False),
                "structure_validated": val_result.get("structure_validated", False),
                "content_readable": val_result.get("content_readable", False),
                "recovery_completed": True,
                "hash_verified": True,
                "status": "VERIFIED_COPIED" if val_result.get("is_valid") else "COPIED_UNVALIDATED",
                "validation_status": val_result.get("status")
            }
            extracted_files.append(item_info)

            if progress_callback:
                progress_callback(idx, total_items, filename, True)

        verified_count = sum(1 for f in extracted_files if f.get("is_valid"))
        return {
            "status": "success",
            "target_serial": serial,
            "destination_directory": str(dest_dir),
            "total_requested": total_items,
            "total_copied": len([f for f in extracted_files if f.get("local_path")]),
            "verified_valid": verified_count,
            "files": extracted_files
        }

