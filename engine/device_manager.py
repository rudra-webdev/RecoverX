"""
Android Device Manager for RecoverX
Discovers and profiles connected Android devices via read-only ADB commands.
"""
import re
from typing import List, Dict, Any, Optional
from utils.adb import ADBClient
from utils.logging_config import logger

class DeviceManager:
    def __init__(self, adb_client: Optional[ADBClient] = None, dry_run: bool = False):
        self.adb = adb_client or ADBClient(dry_run=dry_run)

    def get_connected_devices(self) -> List[Dict[str, str]]:
        """Queries ADB for all connected target devices."""
        return self.adb.list_devices()

    def inspect_device(self, serial: Optional[str] = None) -> Dict[str, Any]:
        """
        Gathers comprehensive device details via safe read-only getprop and shell queries.
        If serial is omitted, inspects the first available device.
        """
        devices = self.get_connected_devices()
        is_dry = getattr(self.adb, "dry_run", False)
        if not devices and not is_dry:
            return {"status": "error", "message": "No Android devices connected or authorized via ADB."}

        target_serial = serial or (devices[0]["serial"] if devices else "DRYRUN_SIMULATED_SERIAL")
        target_state = next((d["state"] for d in devices if d["serial"] == target_serial), "device" if is_dry else "unknown")

        if target_state != "device":
            return {
                "status": "unauthorized_or_offline",
                "serial": target_serial,
                "state": target_state,
                "message": f"Device {target_serial} is in state '{target_state}'. Please accept the USB debugging prompt on the phone screen."
            }

        logger.info(f"Inspecting Android device: {target_serial}")

        # Safe read-only properties
        props_raw = self.adb.shell(target_serial, "getprop")
        props = self._parse_getprop(props_raw)

        # Storage filesystem info
        df_output = self.adb.shell(target_serial, "df -h /sdcard /storage/emulated/0 2>/dev/null || df /sdcard")
        
        # SELinux and security status
        selinux = self.adb.shell(target_serial, "getenforce 2>/dev/null").strip()
        
        # Check root status safely without executing su
        su_check = self.adb.shell(target_serial, "which su 2>/dev/null").strip()
        is_rooted = bool(su_check and "not found" not in su_check.lower() and "/su" in su_check)

        # Bootloader state detection
        locked_state = props.get("ro.boot.flash.locked") or props.get("ro.boot.verifiedbootstate") or "locked (presumed)"
        if locked_state in ("1", "locked"):
            bootloader_status = "Locked"
        elif locked_state in ("0", "unlocked", "orange"):
            bootloader_status = "Unlocked"
        else:
            bootloader_status = str(locked_state)

        # File-Based Encryption (FBE) & Storage Security
        sdk_int = int(props.get("ro.build.version.sdk", "0") or 0)
        crypto_type = props.get("ro.crypto.type", "file" if sdk_int >= 29 else "block")
        crypto_state = props.get("ro.crypto.state", "encrypted")
        fbe_active = (crypto_type == "file")

        # Scoped Storage (Android 11+ / SDK 30+)
        scoped_storage = sdk_int >= 30

        # Xiaomi / MIUI / HyperOS detection
        is_xiaomi = props.get("ro.product.manufacturer", "").lower() in ("xiaomi", "redmi", "poco")
        miui_version = props.get("ro.miui.ui.version.name")
        hyperos_version = props.get("ro.mi.os.version.name") or props.get("ro.hyper.os.version.name")
        os_flavor = "Stock Android"
        if miui_version:
            os_flavor = f"Xiaomi MIUI {miui_version}"
        elif hyperos_version:
            os_flavor = f"Xiaomi HyperOS {hyperos_version}"
        elif is_xiaomi:
            os_flavor = "Xiaomi Custom Android"

        # Detect Removable SD card mount on Android
        sd_card_mount = None
        if df_output:
            for line in df_output.splitlines():
                sd_match = re.search(r"(/storage/[A-F0-9]{4}-[A-F0-9]{4})", line)
                if sd_match:
                    sd_card_mount = sd_match.group(1)
                    break

        device_profile = {
            "status": "success",
            "serial": target_serial,
            "manufacturer": props.get("ro.product.manufacturer", "Unknown"),
            "model": props.get("ro.product.model", "Unknown"),
            "device_codename": props.get("ro.product.device", "Unknown"),
            "market_name": props.get("ro.product.marketname", props.get("ro.product.model", "Unknown")),
            "android_version": props.get("ro.build.version.release", "Unknown"),
            "sdk_version": props.get("ro.build.version.sdk", "Unknown"),
            "security_patch": props.get("ro.build.version.security_patch", "Unknown"),
            "build_id": props.get("ro.build.display.id", "Unknown"),
            "cpu_abi": props.get("ro.product.cpu.abi", "Unknown"),
            "os_flavor": os_flavor,
            "selinux_mode": selinux or "Enforcing",
            "root_status": "Non-Rooted (Secure)" if not is_rooted else "Root Binary Present",
            "is_rooted": is_rooted,
            "bootloader_status": bootloader_status,
            "fbe_status": "Hardware-backed File-Based Encryption (FBE) Active" if fbe_active else f"Encryption: {crypto_state}",
            "fbe_active": fbe_active,
            "scoped_storage": "Strict Scoped Storage Enforced (Android 11+)" if scoped_storage else "Legacy Storage Access",
            "scoped_storage_active": scoped_storage,
            "removable_sd_card_mount": sd_card_mount,
            "storage_summary": df_output.strip().splitlines() if df_output else [],
            "forensic_limitations": [
                "Raw block storage (/dev/block/bootdevice/by-name/userdata) is restricted by Android SELinux and Linux kernel DAC.",
                "Under standard Android FBE implementations (API 29+), file deletion initiates kernel key eviction. While plaintext reconstruction from internal storage without valid keys is technically infeasible via standard forensic software, recoverability is governed by partition encryption status, RAM key persistence, and wear-leveling behaviors.",
                "Private application sandboxes (/data/data/com.whatsapp) cannot be accessed without root privileges or application-directed backups.",
                "Flash storage uses TRIM / flash translation layer wear-leveling that zeros unlinked ext4/f2fs blocks.",
                "RecoverX adheres to non-destructive forensics and operates within authorized logical boundaries."
            ]
        }

        return device_profile

    def _parse_getprop(self, raw_output: str) -> Dict[str, str]:
        """Parses [key]: [value] lines from adb shell getprop."""
        props = {}
        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith("[") and "]: [" in line:
                k, v = line.split("]: [", 1)
                key = k.lstrip("[").strip()
                val = v.rstrip("]").strip()
                props[key] = val
        return props

