import os
import sys
import subprocess
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.burn import _secure_dir_permissions, _secure_file_permissions, BurnDB

def test_secure_dir_permissions_posix(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    
    test_dir = tmp_path / "restricted_dir"
    _secure_dir_permissions(test_dir)
    
    assert test_dir.exists()
    if os.name != "nt":
        mode = os.stat(test_dir).st_mode & 0o777
        assert mode == 0o700

def test_secure_file_permissions_posix(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    
    test_file = tmp_path / "restricted_file.txt"
    test_file.write_text("secrets")
    _secure_file_permissions(test_file)
    
    if os.name != "nt":
        mode = os.stat(test_file).st_mode & 0o777
        assert mode == 0o600

def test_secure_permissions_windows(tmp_path, monkeypatch):
    if sys.platform != "win32":
        pytest.skip("Windows-only permission checks")
        
    monkeypatch.setattr(sys, "platform", "win32")
    
    # Test directory permissions
    test_dir = tmp_path / "win_restricted_dir"
    _secure_dir_permissions(test_dir)
    assert test_dir.exists()
    
    # Verify that inheritance is disabled on Windows
    result = subprocess.run(["icacls", str(test_dir)], capture_output=True, text=True, check=True)
    # Inherited entries are marked with (I). Since inheritance is removed,
    # no inherited entries should remain for standard users.
    assert "(I)" not in result.stdout
    
    # Test file permissions
    test_file = test_dir / "win_restricted_file.txt"
    test_file.write_text("windows secrets")
    _secure_file_permissions(test_file)
    
    result_file = subprocess.run(["icacls", str(test_file)], capture_output=True, text=True, check=True)
    assert "(I)" not in result_file.stdout

def test_burndb_secures_parent_directory(tmp_path):
    db_dir = tmp_path / "db_parent"
    db_path = db_dir / "sessions.db"
    
    db = BurnDB(db_path)
    
    assert db_dir.exists()
    if os.name != "nt":
        mode = os.stat(db_dir).st_mode & 0o777
        assert mode == 0o700
    else:
        result = subprocess.run(["icacls", str(db_dir)], capture_output=True, text=True, check=True)
        assert "(I)" not in result.stdout
