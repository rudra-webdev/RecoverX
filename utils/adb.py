"""
ADB Safe Read-Only Automation Wrapper for RecoverX
Enforces strict read-only digital forensic investigation constraints,
an explicit command allowlist, dry-run simulation, and denylist protections.
"""
import subprocess
import os
import re
import shlex
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from config import ADB_PATH, DRY_RUN, ENFORCE_ADB_ALLOWLIST
from utils.logging_config import logger

FORBIDDEN_KEYWORDS = [
    "root",
    "remount",
    "install",
    "uninstall",
    "push",
    "format",
    "mkfs",
    "fastboot",
    "reboot",
    "recovery",
    "bootloader",
    "sideload",
    "flash",
    "erase",
    "unlock",
    "oem unlock",
    "disable-verity",
    "enable-verity",
    "dd of=",
    "rm ",
    "rmdir",
    "chmod",
    "chown",
    "setprop",
    "wipe",
    ">>",       # Prevents file appending on phone filesystem
    "tee ",     # Prevents file writing via tee
    "touch ",   # Prevents file creation
    "mkdir ",   # Prevents directory creation
    "cp ",      # Prevents file copy
    "mv ",      # Prevents file move
]

# Strict Allowlist: Only approved top-level ADB subcommands
ALLOWED_ADB_TOP_LEVEL_COMMANDS: Set[str] = {
    "version",
    "devices",
    "shell",
    "pull"
}

# Strict Allowlist: Only approved read-only Linux binaries on Android target
ALLOWED_SHELL_BINARIES: Set[str] = {
    "getprop",
    "getenforce",
    "which",
    "df",
    "ls",
    "find",
    "stat",
    "wc",
    "head"
}

class ADBExecutionError(Exception):
    pass

class ADBClient:
    def __init__(self, adb_path: str = ADB_PATH, dry_run: bool = DRY_RUN):
        self.adb_path = adb_path
        self.dry_run = dry_run

    def is_available(self) -> bool:
        """Verifies if the ADB executable exists and can run."""
        try:
            self.validate_adb_command(["version"])
            res = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return res.returncode == 0
        except Exception:
            return False

    @staticmethod
    def validate_serial(serial: str) -> str:
        """
        Validates target device serial number against injection metacharacters.
        Allows only alphanumeric characters, dots, colons, underscores, and hyphens.
        """
        if not serial or not isinstance(serial, str):
            raise PermissionError("Forensic Safety Violation: Empty or invalid ADB device serial.")
        if not re.match(r"^[A-Za-z0-9\.\:\-_]+$", serial):
            raise PermissionError(
                f"Forensic Safety Violation: Device serial '{serial}' contains prohibited metacharacters."
            )
        return serial

    def validate_adb_command(self, args: List[str]):
        """
        Validates ADB arguments against both the strict allowlist and safety denylist.
        Raises PermissionError if any unapproved or destructive command is attempted.
        """
        cmd_str = " ".join(args)
        cmd_str_lower = cmd_str.lower()

        # Prohibit command substitutions
        if "`" in cmd_str or "$(" in cmd_str:
            raise PermissionError(
                "Forensic Safety Violation: Command substitution ($() or backticks) is strictly forbidden in ADB commands."
            )

        # 1. Check Denylist Keywords
        for forbidden in FORBIDDEN_KEYWORDS:
            if forbidden in cmd_str_lower:
                raise PermissionError(
                    f"Forensic Safety Violation: Command containing prohibited token '{forbidden}' is strictly blocked in RecoverX."
                )

        # Prohibit write redirections to any target except /dev/null
        # Matches any > not part of 2>&1 or >/dev/null or > /dev/null
        redirect_matches = re.findall(r"(?<!2)(?<!1)(?<!\s2)(?<!\s1)>\s*(\S+)", cmd_str)
        for target in redirect_matches:
            target_clean = target.strip("&1")
            if target_clean and target_clean != "/dev/null":
                raise PermissionError(
                    f"Forensic Safety Violation: Shell write redirection to target '{target}' is strictly forbidden."
                )

        if not ENFORCE_ADB_ALLOWLIST:
            return

        # 2. Check Top-Level Command Allowlist
        # Determine actual subcommand (skipping global flags like -s <serial>)
        clean_args = []
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg in ("-s", "-p", "-t"):
                skip_next = True
                continue
            clean_args.append(arg)

        if not clean_args:
            raise PermissionError("Forensic Safety Violation: Empty ADB command invocation.")

        subcommand = clean_args[0].lower()
        if subcommand not in ALLOWED_ADB_TOP_LEVEL_COMMANDS:
            raise PermissionError(
                f"Forensic Allowlist Violation: ADB subcommand '{subcommand}' is not in the approved allowlist: {sorted(list(ALLOWED_ADB_TOP_LEVEL_COMMANDS))}"
            )

        # 3. For 'shell' commands, validate every individual command pipeline
        if subcommand == "shell" and len(clean_args) > 1:
            raw_shell_cmd = " ".join(clean_args[1:])
            self._validate_shell_pipeline(raw_shell_cmd)

    def _validate_shell_pipeline(self, shell_cmd: str):
        """
        Validates shell pipeline commands against ALLOWED_SHELL_BINARIES.
        Ensures each segment of a pipe or boolean chain (| or ||) starts with an approved binary.
        """
        # Split command by pipelines, chained commands, and newlines (|, ||, ;, &&, \n, \r)
        segments = re.split(r"\|\||\||&&|;|\n|\r", shell_cmd)
        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue

            # Strip leading redirection or subshell characters
            cleaned_seg = seg.lstrip("(")
            tokens = cleaned_seg.split()
            if not tokens:
                continue

            primary_bin = tokens[0].lower().lstrip("./").split("/")[-1]
            if primary_bin not in ALLOWED_SHELL_BINARIES:
                raise PermissionError(
                    f"Forensic Allowlist Violation: Shell binary '{primary_bin}' in command '{seg}' is not authorized. "
                    f"Allowed binaries: {sorted(list(ALLOWED_SHELL_BINARIES))}"
                )

            # Extra defense-in-depth: check for rm keyword in any argument
            if re.search(r"\brm\b", seg, re.IGNORECASE):
                raise PermissionError(
                    f"Forensic Safety Violation: 'rm' token in segment '{seg}' is strictly prohibited."
                )

    def run_command(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Executes an adb command safely with allowlist and dry-run enforcement."""
        self.validate_adb_command(args)
        full_cmd = [self.adb_path] + args

        if self.dry_run:
            print(f"[DRY-RUN] Executing: {' '.join(full_cmd)}")
            logger.info(f"[DRY-RUN] ADB command preview: {' '.join(full_cmd)}")
            return subprocess.CompletedProcess(
                args=full_cmd,
                returncode=0,
                stdout="[DRY-RUN-SIMULATED-OUTPUT]\n",
                stderr=""
            )

        logger.debug(f"Executing ADB command: {' '.join(full_cmd)}")
        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace"
            )
            return res
        except subprocess.TimeoutExpired:
            raise ADBExecutionError(f"ADB command timed out after {timeout} seconds: {' '.join(full_cmd)}")
        except Exception as e:
            raise ADBExecutionError(f"ADB command execution failed: {e}")

    def list_devices(self) -> List[Dict[str, str]]:
        """Lists connected devices and their authorization state."""
        try:
            res = self.run_command(["devices", "-l"], timeout=10)
        except Exception as e:
            logger.warning(f"Could not query adb devices: {e}")
            return []

        devices = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("*") or line.startswith("List of devices") or "[DRY-RUN" in line:
                continue

            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                state = parts[1]
                details = {}
                for part in parts[2:]:
                    if ":" in part:
                        k, v = part.split(":", 1)
                        details[k] = v
                devices.append({
                    "serial": serial,
                    "state": state,
                    "product": details.get("product", "Unknown"),
                    "model": details.get("model", "Unknown"),
                    "device": details.get("device", "Unknown"),
                    "transport_id": details.get("transport_id", "")
                })
        return devices

    def shell(self, serial: str, command: str, timeout: int = 30) -> str:
        """Executes a safe read-only shell command on the specified device."""
        safe_serial = self.validate_serial(serial)
        args = ["-s", safe_serial, "shell", command]
        res = self.run_command(args, timeout=timeout)
        return res.stdout

    def pull_file(self, serial: str, remote_path: str, local_destination: str, timeout: int = 120) -> bool:
        """Pulls a single file or directory from the device to a local destination."""
        safe_serial = self.validate_serial(serial)
        if "`" in remote_path or "$(" in remote_path or ";" in remote_path or "|" in remote_path:
            raise PermissionError(f"Forensic Safety Violation: Remote path '{remote_path}' contains metacharacters.")

        dest_path = Path(local_destination)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        args = ["-s", safe_serial, "pull", remote_path, str(dest_path)]
        res = self.run_command(args, timeout=timeout)
        if self.dry_run:
            return True
        return res.returncode == 0 and dest_path.exists()
