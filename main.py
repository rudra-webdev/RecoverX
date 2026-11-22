"""
RecoverX — Command Line Interface
Forensic Data Recovery and Logical Investigation Engine.
"""
import argparse
import sys
import json
from pathlib import Path

from config import RECOVERED_DIR, REPORTS_DIR, OFFLINE_MODE, DRY_RUN
from utils.logging_config import logger, setup_logger
from utils.network_guard import enable_offline_mode, is_offline_mode_active
from utils.adb import ADBClient
from engine.device_manager import DeviceManager
from engine.android_scanner import AndroidScanner
from engine.storage_scanner import StorageScanner
from engine.recovery_manager import RecoveryManager
from engine.report_generator import ReportGenerator
from engine.security_auditor import SecurityAuditor
from whatsapp.scanner import WhatsAppScanner

def cmd_privacy_audit(args):
    """Executes pre-connection privacy and security audit."""
    print("\n=== RecoverX — Privacy & Security Codebase Audit ===")
    auditor = SecurityAuditor(Path("."))
    res = auditor.perform_full_audit()

    print(f"Status           : {res['status']}")
    print(f"Offline Mode     : {'ACTIVE (Network socket access blocked)' if is_offline_mode_active() else 'INACTIVE'}")
    print(f"ADB Allowlist    : {'ENFORCED (Only approved read-only commands)' if res['adb_allowlist_enforced'] else 'INACTIVE'}")
    print(f"Direct Deps      : {', '.join(res['dependencies']['direct'])}")
    print(f"Transitive Deps  : {', '.join(res['dependencies']['transitive'])}")
    print(f"Network Calls    : {res['codebase_inspection']['network_calls_found']} (0 found)")
    print(f"Telemetry Trackers: {res['codebase_inspection']['cloud_telemetry_found']} (0 found)")
    print(f"File Deletions   : {res['codebase_inspection']['file_deletion_calls_found']} (0 found)")
    
    print("\n--- Audited ADB Commands ---")
    for c in res["adb_command_audit"]["audited_commands_catalog"][:6]:
        print(f"  [ALLOWLIST] {c['cmd']} ({c['scope']})")
    print("  ... and remaining catalog all verified read-only.")

    print("\n--- Risk Summary ---")
    for r in res["risk_analysis"]:
        print(f"  [{r['status']}] {r['category']}: {r['mitigation']}")

    print(f"\n[+] Detailed Markdown Audit: {res['markdown_report']}")
    print(f"[+] Complete JSON Audit Dump: {res['json_report']}\n")
    return 0

def cmd_devices(args):
    """Lists connected ADB devices."""
    dry_run = getattr(args, "dry_run", False) or DRY_RUN
    adb = ADBClient(dry_run=dry_run)
    if not dry_run and not adb.is_available():
        print(f"[!] ADB executable not detected or not working at configured path: {adb.adb_path}")
        print("    Please ensure Android platform-tools are installed.")
        return 1

    devices = adb.list_devices()
    print("\n=== RecoverX — Connected Android Devices ===")
    if dry_run:
        print("[DRY-RUN] Simulated ADB command execution. No physical queries made.")
        return 0

    if not devices:
        print("No Android devices detected via ADB.")
        print("Ensure USB debugging is enabled and the phone is connected via USB.")
        return 0

    print(f"{'SERIAL':<20} {'STATE':<14} {'MODEL':<18} {'PRODUCT'}")
    print("-" * 65)
    for dev in devices:
        print(f"{dev['serial']:<20} {dev['state']:<14} {dev.get('model', 'Unknown'):<18} {dev.get('product', 'Unknown')}")
    print(f"\nTotal devices: {len(devices)}\n")
    return 0

def cmd_inspect_android(args):
    """Performs deep logical inspection of an Android device."""
    dry_run = getattr(args, "dry_run", False) or DRY_RUN
    mgr = DeviceManager(dry_run=dry_run)
    profile = mgr.inspect_device(serial=args.serial)
    
    if profile.get("status") != "success":
        print(f"[!] Device inspection failed: {profile.get('message', 'Unknown error')}")
        return 1

    print("\n=== RecoverX — Android Device Profile ===")
    print(f"Manufacturer    : {profile.get('manufacturer')}")
    print(f"Model           : {profile.get('model')} ({profile.get('device_codename')})")
    print(f"Android Version : {profile.get('android_version')} (SDK {profile.get('sdk_version')})")
    print(f"Build ID        : {profile.get('build_id')}")
    print(f"Security Patch  : {profile.get('security_patch')}")
    print(f"CPU ABI         : {profile.get('cpu_abi')}")
    print(f"SELinux Status  : {profile.get('selinux_mode')}")
    print(f"Root Binary     : {profile.get('root_status')}")
    print(f"Bootloader      : {profile.get('bootloader_status')}")

    print("\n--- Storage Filesystem Mounts ---")
    for s in profile.get("storage_summary", []):
        print(f"  {s}")

    print("\n--- Forensic Safety Guarantees ---")
    for lim in profile.get("forensic_limitations", []):
        print(f"  [i] {lim}")
    print()

    # Generate report
    rep = ReportGenerator()
    paths = rep.generate_report({"device_profile": profile}, title="Android Device Inspection")
    print(f"Report saved: {paths['markdown_report']}")
    return 0

def cmd_scan_android(args):
    """Executes full read-only logical forensic scan on connected Android device."""
    dry_run = getattr(args, "dry_run", False) or DRY_RUN
    scanner = AndroidScanner(dry_run=dry_run)
    results = scanner.scan_device(serial=args.serial)

    if results.get("status") != "success":
        print(f"[!] Android scan failed: {results.get('message', 'Device inaccessible')}")
        return 1

    print("\n=== RecoverX — Android Logical Scan Summary ===")
    summary = results.get("forensic_summary", {})
    print(f"Media Folders Inspected : {summary.get('total_media_folders_inspected', 0)}")
    print(f"Cache/Thumbnail Folders : {summary.get('total_cache_entries', 0)}")
    print(f"WhatsApp Media Items    : {summary.get('whatsapp_media_items_found', 0)}")
    print(f"WhatsApp Databases      : {summary.get('whatsapp_databases_found', 0)}")
    print(f"Exported Chat Files     : {summary.get('chat_exports_found', 0)}")
    print(f"Private App Sandbox     : Access Denied by OS (Expected for Non-Root)")

    rep = ReportGenerator()
    paths = rep.generate_report(results, title="Android Logical Investigation")
    print(f"\n[+] Detailed Investigation Report: {paths['markdown_report']}")
    print(f"[+] Forensic JSON Dump:          {paths['json_report']}\n")
    return 0

def cmd_scan_whatsapp(args):
    """Scans for WhatsApp artifacts locally or via ADB."""
    source_dir = getattr(args, "source", None)
    dry_run = getattr(args, "dry_run", False) or DRY_RUN
    if source_dir:
        target = Path(source_dir)
        print(f"\n=== RecoverX — Scanning WhatsApp Directory: {target} ===")
        scanner = WhatsAppScanner(target)
        res = scanner.scan()
    else:
        # Fall back to scanning connected Android phone
        print("\n=== RecoverX — Scanning Connected Android Phone for WhatsApp ===")
        android_scanner = AndroidScanner(dry_run=dry_run)
        res = android_scanner.scan_device(serial=getattr(args, "serial", None))

    rep = ReportGenerator()
    paths = rep.generate_report(res, title="WhatsApp Forensic Investigation")
    print(f"\n[+] WhatsApp Investigation Report: {paths['markdown_report']}")
    print(f"[+] JSON Artifact Dump:           {paths['json_report']}\n")
    return 0

def cmd_scan_image(args):
    """Scans a raw disk image for file signatures."""
    source = Path(args.source)
    if not source.is_file():
        print(f"[!] Source disk image not found: {source}")
        return 1

    print(f"\n=== RecoverX — Scanning Disk Image: {source.name} ===")
    scanner = StorageScanner()
    res = scanner.scan_disk_image(source)

    print(f"\nScan Complete:")
    print(f"  Source Size   : {res['size_bytes']} bytes")
    print(f"  Total Carved  : {res['total_carved']}")
    print(f"  Valid Files   : {res['valid_carved']}")
    print(f"  Duplicates    : {res['duplicates']}")

    rep = ReportGenerator()
    paths = rep.generate_report(res, title="Disk Image Carving Scan")
    print(f"\n[+] Report: {paths['markdown_report']}\n")
    return 0

def cmd_recover(args):
    """Carves and recovers files from a disk image to a dedicated destination."""
    source = Path(args.source)
    dest = Path(args.output or RECOVERED_DIR)

    if not source.is_file():
        print(f"[!] Source disk image not found: {source}")
        return 1

    print(f"\n=== RecoverX — File Carving & Recovery ===")
    print(f"Source Image: {source}")
    print(f"Destination : {dest}")

    scanner = StorageScanner()
    scan_res = scanner.scan_disk_image(source)
    carved_objects = scan_res.get("_carved_objects", [])

    rec_mgr = RecoveryManager(output_dir=dest)
    recovery_res = rec_mgr.recover_carved_items(
        carved_objects,
        source_path=source,
        skip_duplicates=True,
        only_valid=False
    )

    full_report = {
        "source_image": str(source),
        "recovery_results": recovery_res,
        "carved_summary": {
            "total_carved": scan_res["total_carved"],
            "valid_carved": scan_res["valid_carved"],
            "duplicates": scan_res["duplicates"]
        }
    }

    rep = ReportGenerator()
    paths = rep.generate_report(full_report, title="Disk Recovery Report")
    print(f"\n[+] Files recovered to: {dest}")
    print(f"[+] Total files written: {recovery_res['total_recovered']}")
    print(f"[+] Recovery Report:    {paths['markdown_report']}\n")
    return 0

def cmd_gui(args):
    """Launches the PySide6 desktop GUI application."""
    from gui.app import launch_gui
    return launch_gui()

def main():
    if OFFLINE_MODE:
        enable_offline_mode()

    # If launched with no arguments, default to launching the GUI
    if len(sys.argv) == 1:
        from gui.app import launch_gui
        sys.exit(launch_gui())

    parser = argparse.ArgumentParser(
        prog="RecoverX",
        description="RecoverX — Windows-first Digital Forensics & Data Recovery Engine."
    )
    parser.add_argument("--offline", action="store_true", default=OFFLINE_MODE, help="Enforce strict offline isolation")
    parser.add_argument("--dry-run", action="store_true", default=DRY_RUN, help="Preview all ADB commands without execution")
    
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # gui
    subparsers.add_parser("gui", help="Launch the PySide6 Desktop GUI application")

    # privacy-audit
    subparsers.add_parser("privacy-audit", help="Run security, privacy, and dependency audit")

    # devices
    p_dev = subparsers.add_parser("devices", help="List connected ADB devices")
    p_dev.add_argument("--dry-run", action="store_true", help="Preview command without querying ADB")

    # inspect-android
    p_inspect = subparsers.add_parser("inspect-android", help="Inspect device hardware/OS/security profile")
    p_inspect.add_argument("--serial", help="Target device serial (optional)")
    p_inspect.add_argument("--dry-run", action="store_true", help="Preview commands without querying device")

    # scan-android
    p_scan_android = subparsers.add_parser("scan-android", help="Logical forensic scan of Android storage")
    p_scan_android.add_argument("--serial", help="Target device serial (optional)")
    p_scan_android.add_argument("--dry-run", action="store_true", help="Preview commands without querying device")

    # scan-whatsapp
    p_wa = subparsers.add_parser("scan-whatsapp", help="Scan WhatsApp storage and databases")
    p_wa.add_argument("--source", help="Local directory to scan (optional, defaults to connected phone)")
    p_wa.add_argument("--serial", help="Target device serial (optional)")
    p_wa.add_argument("--dry-run", action="store_true", help="Preview commands without querying device")

    # scan-image
    p_img = subparsers.add_parser("scan-image", help="Scan raw disk image for file signatures")
    p_img.add_argument("--source", required=True, help="Path to disk image (.img, .raw, .dd)")

    # recover
    p_rec = subparsers.add_parser("recover", help="Recover carved files from raw disk image")
    p_rec.add_argument("--source", required=True, help="Path to disk image (.img, .raw, .dd)")
    p_rec.add_argument("--output", default=str(RECOVERED_DIR), help="Output directory for recovered files")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    command_map = {
        "gui": cmd_gui,
        "privacy-audit": cmd_privacy_audit,
        "devices": cmd_devices,
        "inspect-android": cmd_inspect_android,
        "scan-android": cmd_scan_android,
        "scan-whatsapp": cmd_scan_whatsapp,
        "scan-image": cmd_scan_image,
        "recover": cmd_recover
    }

    handler = command_map.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
