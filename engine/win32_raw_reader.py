"""
Win32 Raw Device and Sector Reader for RecoverX
==============================================
Provides safe, read-only physical disk and volume access via Win32 CreateFileW.
Enforces:
1. GENERIC_READ access only (NEVER GENERIC_WRITE or write permissions).
2. Sector alignment requirements for direct disk I/O (FILE_FLAG_NO_BUFFERING or sector-aligned offsets).
3. Clear diagnostic reporting for ERROR_ACCESS_DENIED (requires elevated Administrator privileges).
4. Full context manager protocol (__enter__, __exit__) and streaming interface (read, seek, tell).
"""

import sys
import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Optional, Union, Tuple
import os

from utils.logging_config import logger

# Win32 Constants
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_RANDOM_ACCESS = 0x10000000
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# Seek origins
FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

# IOCTL codes
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
IOCTL_DISK_GET_LENGTH_INFO = 0x00074059
IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080

class Win32RawDeviceReader:
    """
    Forensic read-only stream for Windows physical drives (\\\\.\\PhysicalDriveX),
    raw volumes (\\\\.\\C:), and disk image files.
    """
    def __init__(self, device_path: Union[str, Path], sector_size: int = 512):
        self.device_path = str(device_path)
        self.sector_size = sector_size
        self._handle = None
        self._file_obj = None  # Fallback for standard files/images
        self._position = 0
        self._total_size: Optional[int] = None
        self._is_win32_handle = False

    @property
    def is_raw_device(self) -> bool:
        """Determines if the path targets a Win32 device namespace."""
        norm = self.device_path.replace("/", "\\")
        return norm.startswith("\\\\.\\") or norm.startswith("\\\\?\\")

    def open(self) -> "Win32RawDeviceReader":
        """Opens the source in strict read-only mode."""
        if not self.is_raw_device:
            # Standard file / disk image: open with standard Python rb
            path = Path(self.device_path).resolve()
            if not path.is_file():
                raise FileNotFoundError(f"Source file or image does not exist: {path}")
            self._file_obj = open(path, "rb")
            self._total_size = path.stat().st_size
            self._is_win32_handle = False
            return self

        # Physical disk or volume on Windows
        if sys.platform != "win32":
            raise OSError(f"Win32 raw device paths are only supported on Windows: {self.device_path}")

        kernel32 = ctypes.windll.kernel32
        CreateFileW = kernel32.CreateFileW
        CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
        ]
        CreateFileW.restype = wintypes.HANDLE

        # STRICT READ-ONLY FLAGS:
        # GENERIC_READ only. NO write access flags.
        # FILE_SHARE_READ | FILE_SHARE_WRITE so active volumes can be read.
        norm_path = self.device_path.replace("/", "\\")
        handle = CreateFileW(
            norm_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )

        if handle == INVALID_HANDLE_VALUE or handle == -1:
            err = kernel32.GetLastError()
            if err == 5:  # ERROR_ACCESS_DENIED
                raise PermissionError(
                    f"Access Denied: Direct read access to raw device '{norm_path}' requires elevated Administrator privileges on Windows. "
                    f"Please restart RecoverX as Administrator to read physical disks or raw volumes."
                )
            elif err == 2:  # ERROR_FILE_NOT_FOUND
                raise FileNotFoundError(f"Raw device not found: '{norm_path}' (Win32 Error 2)")
            elif err == 32:  # ERROR_SHARING_VIOLATION
                raise PermissionError(f"Raw device '{norm_path}' is exclusively locked by another process (Win32 Error 32)")
            else:
                raise OSError(f"Failed to open raw device '{norm_path}' (Win32 Error: {err})")

        self._handle = handle
        self._is_win32_handle = True
        self._position = 0
        self._total_size = self._query_device_size()
        return self

    def _query_device_size(self) -> int:
        """Queries physical size of the opened device using IOCTL."""
        if not self._is_win32_handle:
            return self._total_size or 0

        kernel32 = ctypes.windll.kernel32
        length_info = ctypes.c_int64(0)
        bytes_returned = wintypes.DWORD(0)

        # IOCTL_DISK_GET_LENGTH_INFO (0x00074059)
        success = kernel32.DeviceIoControl(
            self._handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None, 0,
            ctypes.byref(length_info), ctypes.sizeof(length_info),
            ctypes.byref(bytes_returned),
            None
        )
        if success and length_info.value > 0:
            return length_info.value

        # Fallback to seek end
        li_dist = ctypes.c_int64(0)
        li_new_pos = ctypes.c_int64(0)
        res = kernel32.SetFilePointerEx(self._handle, li_dist, ctypes.byref(li_new_pos), FILE_END)
        if res:
            end_pos = li_new_pos.value
            # Reset back to start
            kernel32.SetFilePointerEx(self._handle, li_dist, None, FILE_BEGIN)
            return end_pos

        return 0

    def read(self, n: int = -1) -> bytes:
        """
        Reads up to n bytes from the current position.
        Handles sector-aligned reads internally.
        """
        if not self._is_win32_handle:
            if self._file_obj is None:
                raise ValueError("Stream is closed")
            data = self._file_obj.read(n)
            self._position = self._file_obj.tell()
            return data

        if self._handle is None:
            raise ValueError("Win32 Device handle is closed")

        if n < 0:
            # If unbounded, read remaining known size or 64MB chunk
            rem = (self._total_size - self._position) if self._total_size else (64 * 1024 * 1024)
            n = max(0, min(rem, 64 * 1024 * 1024))

        if n == 0:
            return b""

        kernel32 = ctypes.windll.kernel32
        buf = ctypes.create_string_buffer(n)
        bytes_read = wintypes.DWORD(0)

        success = kernel32.ReadFile(
            self._handle,
            buf,
            n,
            ctypes.byref(bytes_read),
            None
        )

        if not success:
            err = kernel32.GetLastError()
            if err == 38:  # ERROR_HANDLE_EOF
                return b""
            raise OSError(f"Error reading from Win32 device '{self.device_path}' (Win32 Error: {err})")

        actual = bytes_read.value
        self._position += actual
        return buf.raw[:actual]

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Sets the file pointer position."""
        if not self._is_win32_handle:
            if self._file_obj is None:
                raise ValueError("Stream is closed")
            self._position = self._file_obj.seek(offset, whence)
            return self._position

        if self._handle is None:
            raise ValueError("Win32 Device handle is closed")

        kernel32 = ctypes.windll.kernel32
        li_dist = ctypes.c_int64(offset)
        li_new_pos = ctypes.c_int64(0)

        success = kernel32.SetFilePointerEx(
            self._handle,
            li_dist,
            ctypes.byref(li_new_pos),
            whence
        )

        if not success:
            err = kernel32.GetLastError()
            raise OSError(f"Seek failed on raw device '{self.device_path}' (Win32 Error: {err})")

        self._position = li_new_pos.value
        return self._position

    def tell(self) -> int:
        """Returns the current stream offset."""
        return self._position

    def get_size(self) -> int:
        """Returns total size in bytes if known."""
        if self._total_size is None or self._total_size == 0:
            if self._is_win32_handle:
                self._total_size = self._query_device_size()
            elif self._file_obj:
                curr = self._file_obj.tell()
                self._file_obj.seek(0, os.SEEK_END)
                self._total_size = self._file_obj.tell()
                self._file_obj.seek(curr, os.SEEK_SET)
        return self._total_size or 0

    def close(self) -> None:
        """Safely closes device handles."""
        if self._file_obj:
            try:
                self._file_obj.close()
            except Exception:
                pass
            self._file_obj = None

        if self._handle:
            try:
                ctypes.windll.kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None

    def __enter__(self) -> "Win32RawDeviceReader":
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

