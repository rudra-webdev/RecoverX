"""
Automated Tests for RecoverX Settings Persistence
Tests loading, saving, and applying custom toolpaths and forensic configurations.
"""
import pytest
from pathlib import Path
import json
from unittest.mock import patch

from config import save_user_settings, load_user_settings
import config

def test_save_and_load_user_settings(tmp_path: Path):
    """Tests saving settings dictionary to JSON and reading it back."""
    test_config_file = tmp_path / "test_config.json"
    
    with patch("config.CONFIG_FILE", test_config_file):
        test_settings = {
            "photorec_path": r"C:\Tools\photorec_win.exe",
            "tsk_bin_dir": r"C:\Tools\tsk",
            "dry_run_default": True
        }
        success = save_user_settings(test_settings)
        assert success is True
        assert test_config_file.exists()

        loaded = load_user_settings()
        assert loaded["photorec_path"] == r"C:\Tools\photorec_win.exe"
        assert loaded["tsk_bin_dir"] == r"C:\Tools\tsk"
        assert loaded["dry_run_default"] is True

def test_settings_view_save_action(qapp, tmp_path: Path):
    """Tests that SettingsView UI correctly saves and persists changes."""
    from gui.views.settings_view import SettingsView
    
    test_config_file = tmp_path / "ui_test_config.json"
    with patch("config.CONFIG_FILE", test_config_file):
        view = SettingsView()
        view.pr_path_edit.setText(r"C:\Custom\photorec.exe")
        view.tsk_path_edit.setText(r"C:\Custom\tsk")
        view.chk_dry_run_default.setChecked(True)

        with patch("PySide6.QtWidgets.QMessageBox.information") as mock_info:
            view._save_settings()
            assert mock_info.called

        assert test_config_file.exists()
        saved_data = json.loads(test_config_file.read_text(encoding="utf-8"))
        assert saved_data["photorec_path"] == r"C:\Custom\photorec.exe"
        assert saved_data["tsk_bin_dir"] == r"C:\Custom\tsk"
        assert saved_data["dry_run_default"] is True

