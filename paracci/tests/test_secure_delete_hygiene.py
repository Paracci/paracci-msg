import sys
import time
from pathlib import Path
import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))


def test_preview_store_uses_secure_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    from core.preview_store import PreviewStore
    import core.preview_store as preview_store_module
    
    deleted_paths = []
    def mock_secure_delete(path):
        deleted_paths.append(str(path))
        p = Path(path)
        if p.exists():
            p.unlink()
        return True
        
    monkeypatch.setattr(preview_store_module, "secure_delete", mock_secure_delete)
    
    store = PreviewStore()
    token1 = store.generate_token(b"content1", "test1.txt", "text/plain")
    token2 = store.generate_token(b"content2", "test2.txt", "text/plain")
    
    entry1 = store.get(token1)
    file_path1 = entry1.file_path
    
    # Revoke
    store.revoke(token1)
    assert file_path1 in deleted_paths
    
    # Clear
    entry2 = store.get(token2)
    file_path2 = entry2.file_path
    store.clear()
    assert file_path2 in deleted_paths


def test_native_save_grant_store_uses_secure_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    from core.preview_store import NativeSaveGrantStore
    import core.preview_store as preview_store_module
    
    deleted_paths = []
    def mock_secure_delete(path):
        deleted_paths.append(str(path))
        p = Path(path)
        if p.exists():
            p.unlink()
        return True
        
    monkeypatch.setattr(preview_store_module, "secure_delete", mock_secure_delete)
    
    store = NativeSaveGrantStore()
    token = store.issue(b"content", "test.paracci")
    
    entry = store._entries[token]
    file_path = entry.file_path
    
    # Consume
    store.consume(token)
    assert file_path in deleted_paths


def test_device_lock_clears_stores_and_caches(tmp_path, monkeypatch):
    # Setup App
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1")
    
    import app as ag_app
    import app.routes as routes_module
    from core.preview_store import preview_store, native_save_grants
    
    # Mock secure_delete to track files deleted
    deleted_files = []
    
    import core.burn as burn_module
    import core.preview_store as preview_store_module
    
    def mock_secure_delete(path):
        deleted_files.append(str(path))
        p = Path(path)
        if p.exists():
            p.unlink()
        return True
        
    monkeypatch.setattr(burn_module, "secure_delete", mock_secure_delete)
    monkeypatch.setattr(preview_store_module, "secure_delete", mock_secure_delete)
    monkeypatch.setattr(routes_module, "secure_delete", mock_secure_delete)
    
    flask_app = ag_app.create_app(loopback_auth_token="test-token")
    flask_app.config["TESTING"] = True
    
    # Populate stores and caches
    p_token = preview_store.generate_token(b"preview-data", "preview.txt", "text/plain")
    s_token = native_save_grants.issue(b"save-data", "save.paracci")
    
    routes_module.PREVIEW_CACHE["cache_p1"] = {
        "filename": "cache_preview.txt",
        "content_path": Path(tmp_path / "cache_preview_file.bin"),
        "mime": "text/plain",
        "expires": time.time() + 600,
        "allow_download": True,
        "access_token": "token123"
    }
    Path(tmp_path / "cache_preview_file.bin").write_bytes(b"cache-preview-bytes")
    
    routes_module.STAGED_ATTACHMENT_CACHE["cache_s1"] = {
        "filename": "cache_staged.txt",
        "content_path": Path(tmp_path / "cache_staged_file.bin"),
        "expires": time.time() + 600
    }
    Path(tmp_path / "cache_staged_file.bin").write_bytes(b"cache-staged-bytes")
    
    routes_module.NATIVE_FILE_REF_CACHE["ref1"] = {
        "path": "some_path",
        "filename": "some_name",
        "expires": time.time() + 600
    }
    
    # Assert they are populated
    assert len(preview_store._entries) > 0
    assert len(native_save_grants._entries) > 0
    assert len(routes_module.PREVIEW_CACHE) > 0
    assert len(routes_module.STAGED_ATTACHMENT_CACHE) > 0
    assert len(routes_module.NATIVE_FILE_REF_CACHE) > 0
    
    # Call lock_device()
    ag_app.lock_device()
    
    # Assert they are cleared
    assert len(preview_store._entries) == 0
    assert len(native_save_grants._entries) == 0
    assert len(routes_module.PREVIEW_CACHE) == 0
    assert len(routes_module.STAGED_ATTACHMENT_CACHE) == 0
    assert len(routes_module.NATIVE_FILE_REF_CACHE) == 0
    
    # Assert secure_delete was called
    assert len(deleted_files) >= 4
