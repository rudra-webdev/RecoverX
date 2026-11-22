"""
Shared pytest configuration and fixtures for RecoverX.
"""
import pytest
import os
import sys

# Ensure Qt runs offscreen in automated headless test runs
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

@pytest.fixture(scope="session")
def qapp():
    """Initializes a shared QApplication instance for headless GUI tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app

