from pathlib import Path
import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skip(reason="Obsolete: App reverted back to pywebview architecture")
def test_launcher_defaults_to_qml_and_gates_widgets_fallback():
    content = (ROOT / "run.py").read_text(encoding="utf-8")
    assert "desktop.qml_app" in content
    assert "desktop.qt_app" in content
    assert "--ui" in content
    assert "widgets" in content


def test_macos_scaffold_uses_swiftui_worker_boundary():
    mac_root = ROOT / "platform" / "macos" / "ParacciMac"
    required = [
        mac_root / "Package.swift",
        mac_root / "Sources" / "App" / "ParacciMacApp.swift",
        mac_root / "Sources" / "Views" / "ContentView.swift",
        mac_root / "Sources" / "Services" / "PythonWorkerClient.swift",
        mac_root / "Sources" / "Support" / "AppKitBridge.swift",
    ]
    for path in required:
        assert path.exists(), f"Missing macOS scaffold file: {path}"

    app = (mac_root / "Sources" / "App" / "ParacciMacApp.swift").read_text(encoding="utf-8")
    content = (mac_root / "Sources" / "Views" / "ContentView.swift").read_text(encoding="utf-8")
    detail = (mac_root / "Sources" / "Views" / "DetailView.swift").read_text(encoding="utf-8")
    store = (mac_root / "Sources" / "Stores" / "ParacciStore.swift").read_text(encoding="utf-8")
    worker = (mac_root / "Sources" / "Services" / "PythonWorkerClient.swift").read_text(encoding="utf-8")
    bridge = (mac_root / "Sources" / "Support" / "AppKitBridge.swift").read_text(encoding="utf-8")
    swift_tests = (mac_root / "Tests" / "PythonWorkerClientTests.swift").read_text(encoding="utf-8")

    assert "SwiftUI" in app
    assert "NavigationSplitView" in content
    assert "NewSessionView" in detail
    assert "ImportSessionView" in detail
    assert "PlaceholderWorkflowView" not in detail
    assert 'method: "session_create"' in store
    assert 'method: "session_import"' in store
    assert 'method: "message_seal"' in store
    assert 'method: "message_open"' in store
    assert "Process()" in worker
    assert "JSONSerialization" in worker
    assert "dataDirectoryURL" in worker
    assert "testDeviceStatusRoundTripAgainstPythonWorker" in swift_tests
    assert "NativeFilePanel" in bridge
    assert "NSOpenPanel" in bridge
    assert "NSSavePanel" in bridge
    assert "sharingType = .none" in bridge

    combined = "\n".join([app, content, detail, store, worker, bridge])
    forbidden = ["WebView", "WKWebView", "localhost", "127.0.0.1"]
    for token in forbidden:
        assert token not in combined
