"""
Device Controller for RecoverX GUI
Asynchronously queries ADB for attached Android devices and profiles.
"""
from PySide6.QtCore import QThread, Signal
from typing import List, Dict, Any, Optional

from engine.device_manager import DeviceManager
from utils.adb import ADBClient
from config import DRY_RUN

class DevicePollWorker(QThread):
    devices_updated = Signal(list)
    device_inspected = Signal(dict)
    error_occurred = Signal(str)

    def __init__(self, dry_run: bool = DRY_RUN, parent=None):
        super().__init__(parent)
        self.dry_run = dry_run
        self.adb = ADBClient(dry_run=dry_run)
        self.mgr = DeviceManager(self.adb, dry_run=dry_run)

    def run(self):
        try:
            devices = self.mgr.get_connected_devices()
            self.devices_updated.emit(devices)
        except Exception as e:
            self.error_occurred.emit(str(e))

