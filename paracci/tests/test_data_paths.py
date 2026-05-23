import importlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import ParacciConfig
from core.shields.linux import LinuxShield
from core.shields.windows import WindowsShield


def load_flask_defaults(monkeypatch, tmp_path: Path, platform_name: str, home: Path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "bootstrap-data"))

    import app as app_module

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(sys, "platform", platform_name)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "paracci"))
    monkeypatch.delenv("DATA_DIR", raising=False)

    return importlib.reload(app_module)


def test_windows_flask_and_shield_use_local_appdata(tmp_path, monkeypatch):
    home = tmp_path / "home"
    local_appdata = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))

    app_module = load_flask_defaults(monkeypatch, tmp_path, "win32", home)
    shield_path = WindowsShield.get_default_data_dir(None, "Paracci")

    assert app_module.DATA_DIR == local_appdata / "Paracci"
    assert Path(shield_path) == app_module.DATA_DIR


def test_windows_flask_and_shield_share_local_fallback(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))

    app_module = load_flask_defaults(monkeypatch, tmp_path, "win32", home)
    shield_path = WindowsShield.get_default_data_dir(None, "Paracci")

    expected = home / "AppData" / "Local" / "Paracci"
    assert app_module.DATA_DIR == expected
    assert Path(shield_path) == expected


def test_linux_flask_and_shield_use_xdg_data_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    xdg_data_home = tmp_path / "xdg-data"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data_home))

    app_module = load_flask_defaults(monkeypatch, tmp_path, "linux", home)
    shield_path = LinuxShield.get_default_data_dir(None, "Paracci")

    assert app_module.DATA_DIR == xdg_data_home / "paracci"
    assert Path(shield_path) == app_module.DATA_DIR


def test_linux_flask_and_shield_share_xdg_fallback(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    app_module = load_flask_defaults(monkeypatch, tmp_path, "linux", home)
    shield_path = LinuxShield.get_default_data_dir(None, "Paracci")

    expected = home / ".local" / "share" / "paracci"
    assert app_module.DATA_DIR == expected
    assert Path(shield_path) == expected


@pytest.mark.parametrize("data_location", ["default_xdg", "custom_xdg", "legacy_config"])
def test_standard_linux_storage_uses_downloads_directory(
    tmp_path, monkeypatch, data_location
):
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    if data_location == "default_xdg":
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        data_dir = home / ".local" / "share" / "paracci"
    elif data_location == "custom_xdg":
        xdg_data_home = tmp_path / "custom-xdg"
        monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data_home))
        data_dir = xdg_data_home / "paracci"
    else:
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        data_dir = home / ".config" / "paracci"

    monkeypatch.setenv("DATA_DIR", str(data_dir))

    config = ParacciConfig()

    assert Path(config.full_downloads_path) == home / "Downloads" / "Paracci"
