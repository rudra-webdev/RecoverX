"""
Windows Drive and Source Selection Manager for RecoverX
Enumerates logical drives, removable USBs, SD cards, and disk images.
Enforces read-only safety, system drive protection, and physical access confirmation.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional
import os
import sys
import ctypes

@dataclass
class StorageSource:
    name: str
    identifier: str  # Drive letter (e.g. "D:\\") or image path
    source_type: str  # "logical_drive", "removable_usb", "sd_card", "disk_image", "physical_drive"
    filesystem: str
    total_bytes: int
    free_bytes: int
    used_bytes: int
    is_system_drive: bool
    is_read_only: bool = True
    requires_confirmation: bool = False
    device_number: Optional[int] = None
    requires_elevation: bool = False
    model_name: Optional[str] = None

    @property
    def total_gb(self) -> float:
        return round(self.total_bytes / (1024 ** 3), 2)

    @property
    def free_gb(self) -> float:
        return round(self.free_bytes / (1024 ** 3), 2)

    @property
    def used_gb(self) -> float:
        return round(self.used_bytes / (1024 ** 3), 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "identifier": self.identifier,
            "source_type": self.source_type,
            "filesystem": self.filesystem,
            "total_bytes": self.total_bytes,
            "free_bytes": self.free_bytes,
            "used_bytes": self.used_bytes,
            "total_gb": self.total_gb,
            "free_gb": self.free_gb,
            "used_gb": self.used_gb,
            "is_system_drive": self.is_system_drive,
            "is_read_only": self.is_read_only,
            "requires_confirmation": self.requires_confirmation,
            "device_number": self.device_number,
            "requires_elevation": self.requires_elevation,
            "model_name": self.model_name
        }

class DriveManager:
    DRIVE_TYPES = {
        0: "Unknown",
        1: "No Root Directory",
        2: "Removable (USB / SD Card)",
        3: "Fixed (HDD / SSD)",
        4: "Network Drive",
        5: "CD-ROM / Optical",
        6: "RAM Disk"
    }

    @classmethod
    def get_system_drive_letter(cls) -> str:
        return os.environ.get("SystemDrive", "C:").upper().rstrip("\\")

    @classmethod
    def list_logical_drives(cls) -> List[StorageSource]:
        """Enumerates accessible Windows logical drives using native Win32 APIs."""
        sources: List[StorageSource] = []
        system_drive = cls.get_system_drive_letter()

        if sys.platform != "win32":
            # POSIX fallback
            return [StorageSource(
                name="Root Filesystem",
                identifier="/",
                source_type="logical_drive",
                filesystem="ext4",
                total_bytes=100 * (1024**3),
                free_bytes=50 * (1024**3),
                used_bytes=50 * (1024**3),
                is_system_drive=True
            )]

        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter_code in range(26):
            if bitmask & (1 << letter_code):
                drive_letter = f"{chr(65 + letter_code)}:\\"
                drive_type_int = ctypes.windll.kernel32.GetDriveTypeW(drive_letter)
                type_name = cls.DRIVE_TYPES.get(drive_type_int, "Unknown")

                # Skip unmounted/optical/network drives
                if drive_type_int in (0, 1, 4, 5):
                    continue

                vol_name_buf = ctypes.create_unicode_buffer(261)
                fs_name_buf = ctypes.create_unicode_buffer(261)
                serial_num = ctypes.c_ulong()
                max_comp_len = ctypes.c_ulong()
                fs_flags = ctypes.c_ulong()

                res = ctypes.windll.kernel32.GetVolumeInformationW(
                    drive_letter,
                    vol_name_buf,
                    ctypes.sizeof(vol_name_buf),
                    ctypes.byref(serial_num),
                    ctypes.byref(max_comp_len),
                    ctypes.byref(fs_flags),
                    fs_name_buf,
                    ctypes.sizeof(fs_name_buf)
                )

                vol_name = vol_name_buf.value if res else "Local Disk"
                fs_type = fs_name_buf.value if res else "Unknown"

                free_bytes_avail = ctypes.c_ulonglong()
                total_bytes = ctypes.c_ulonglong()
                total_free = ctypes.c_ulonglong()

                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    drive_letter,
                    ctypes.byref(free_bytes_avail),
                    ctypes.byref(total_bytes),
                    ctypes.byref(total_free)
                )

                t_bytes = total_bytes.value
                f_bytes = total_free.value
                u_bytes = max(0, t_bytes - f_bytes)
                is_sys = drive_letter.startswith(system_drive)
                is_removable = (drive_type_int == 2)

                s_type = "removable_usb" if is_removable else "logical_drive"
                display_name = f"{vol_name} ({drive_letter.rstrip(os.sep)})" if vol_name else f"Drive ({drive_letter.rstrip(os.sep)})"

                source = StorageSource(
                    name=display_name,
                    identifier=drive_letter,
                    source_type=s_type,
                    filesystem=fs_type,
                    total_bytes=t_bytes,
                    free_bytes=f_bytes,
                    used_bytes=u_bytes,
                    is_system_drive=is_sys,
                    is_read_only=True,
                    requires_confirmation=is_sys
                )
                sources.append(source)

        return sources

    @classmethod
    def is_elevated(cls) -> bool:
        """Checks if current process has Windows Administrator privileges."""
        if sys.platform != "win32":
            return os.geteuid() == 0 if hasattr(os, "geteuid") else False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @classmethod
    def list_physical_drives(cls) -> List[StorageSource]:
        """
        Enumerates physical disks (\\\\.\\PhysicalDrive0, etc.) on Windows.
        Strictly requires explicit confirmation and read-only protection.
        Flags requires_elevation if running without Administrator rights.
        """
        physical_sources: List[StorageSource] = []
        if sys.platform != "win32":
            return physical_sources

        elevated = cls.is_elevated()
        kernel32 = ctypes.windll.kernel32

        # Probe physical drives 0 through 15
        for drive_num in range(16):
            dev_path = f"\\\\.\\PhysicalDrive{drive_num}"
            if elevated:
                CreateFileW = kernel32.CreateFileW
                CreateFileW.argtypes = [
                    ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                    ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE
                ]
                CreateFileW.restype = ctypes.wintypes.HANDLE

                handle = CreateFileW(
                    dev_path,
                    0x80000000,  # GENERIC_READ
                    1 | 2,       # FILE_SHARE_READ | FILE_SHARE_WRITE
                    None,
                    3,           # OPEN_EXISTING
                    0x80,        # FILE_ATTRIBUTE_NORMAL
                    None
                )
                if handle != ctypes.wintypes.HANDLE(-1).value and handle != -1:
                    length_info = ctypes.c_int64(0)
                    ret_bytes = ctypes.wintypes.DWORD(0)
                    kernel32.DeviceIoControl(
                        handle, 0x00074059, None, 0,
                        ctypes.byref(length_info), ctypes.sizeof(length_info),
                        ctypes.byref(ret_bytes), None
                    )
                    sz = length_info.value if length_info.value > 0 else 0
                    kernel32.CloseHandle(handle)

                    is_sys = (drive_num == 0)
                    physical_sources.append(StorageSource(
                        name=f"Physical Drive {drive_num}",
                        identifier=dev_path,
                        source_type="physical_drive",
                        filesystem="Raw / Partitioned",
                        total_bytes=sz,
                        free_bytes=0,
                        used_bytes=sz,
                        is_system_drive=is_sys,
                        is_read_only=True,
                        requires_confirmation=True,
                        device_number=drive_num,
                        requires_elevation=False,
                        model_name=f"Physical Disk #{drive_num}"
                    ))
            else:
                if drive_num == 0:
                    physical_sources.append(StorageSource(
                        name="Physical Drive 0 (Primary Disk)",
                        identifier=dev_path,
                        source_type="physical_drive",
                        filesystem="Raw (Requires Admin)",
                        total_bytes=0,
                        free_bytes=0,
                        used_bytes=0,
                        is_system_drive=True,
                        is_read_only=True,
                        requires_confirmation=True,
                        device_number=0,
                        requires_elevation=True,
                        model_name="Physical Drive 0"
                    ))
                break

        return physical_sources

    @classmethod
    def get_all_sources(cls, include_physical: bool = True) -> List[StorageSource]:
        """Returns all discovered logical drives and physical disks."""
        sources = cls.list_logical_drives()
        if include_physical:
            sources.extend(cls.list_physical_drives())
        return sources

    @classmethod
    def inspect_disk_image(cls, image_path: Path) -> StorageSource:
        """Inspects and validates an existing disk image file."""
        path = Path(image_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Disk image file does not exist: {path}")

        sz = path.stat().st_size
        ext = path.suffix.lower()

        # Check for MBR or VBR signature
        fs = "Raw Image"
        with open(path, "rb") as f:
            header = f.read(512)
            if len(header) >= 512 and header[510:512] == b"\x55\xAA":
                if b"NTFS" in header[:16]:
                    fs = "NTFS (VBR)"
                elif b"FAT" in header[:64]:
                    fs = "FAT (VBR)"
                else:
                    fs = "MBR Partitioned"

        return StorageSource(
            name=f"Image: {path.name}",
            identifier=str(path),
            source_type="disk_image",
            filesystem=fs,
            total_bytes=sz,
            free_bytes=0,
            used_bytes=sz,
            is_system_drive=False,
            is_read_only=True,
            requires_confirmation=False
        )

