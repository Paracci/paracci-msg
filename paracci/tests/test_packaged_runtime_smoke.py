import importlib.util
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_smoke_module():
    module_name = "paracci_packaged_runtime_smoke"
    spec = importlib.util.spec_from_file_location(
        module_name,
        REPO_ROOT / "tools" / "ci" / "packaged_runtime_smoke.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, url: str, body: str = ""):
        self._url = url
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url


def unlock_html(csrf: str, *, offers_linux_fallback: bool) -> str:
    fallback = ""
    if offers_linux_fallback:
        fallback = '<input value="1" name="allow_linux_passphrase_fallback" type="checkbox">'
    return (
        f'<meta content="{csrf}" name="paracci-csrf-token">'
        f'<form id="authForm">{fallback}<input name="pin" type="password"></form>'
    )


def successful_request_recorder(smoke, *, offers_linux_fallback: bool):
    calls = []
    csrf = "csrf-fixture-abcdefghijklmnopqrstuvwxyz1234567890"

    def request(path, form=None, request_csrf=None):
        calls.append((path, form, request_csrf))
        if path == "/unlock" and form is None:
            return FakeResponse(
                "http://127.0.0.1:54321/unlock",
                unlock_html(csrf, offers_linux_fallback=offers_linux_fallback),
            )
        if path == "/unlock":
            return FakeResponse("http://127.0.0.1:54321/unlock/2fa/setup", "2FA setup")
        if path == "/unlock/2fa/setup":
            return FakeResponse("http://127.0.0.1:54321/", "Unlocked")
        if path == "/session/new":
            return FakeResponse(
                f"http://127.0.0.1:54321/session/{'a' * 32}?auto_download=1",
                "Session",
            )
        raise AssertionError(f"Unexpected request path: {path}")

    def fail(message):
        raise smoke.SmokeFailure(message)

    return calls, request, fail


@pytest.mark.parametrize(
    ("platform", "offers_linux_fallback", "expects_consent"),
    [
        ("linux", True, True),
        ("linux", False, False),
        ("windows", True, False),
        ("macos", True, False),
    ],
)
def test_packaged_flow_submits_linux_fallback_consent_only_when_offered(
    platform,
    offers_linux_fallback,
    expects_consent,
):
    smoke = load_smoke_module()
    calls, request, fail = successful_request_recorder(
        smoke,
        offers_linux_fallback=offers_linux_fallback,
    )
    known_secrets = []

    final_url = smoke.complete_authenticated_flow(
        platform,
        request,
        fail,
        known_secrets=known_secrets,
    )

    setup_form = calls[1][1]
    assert final_url.endswith(f"/session/{'a' * 32}?auto_download=1")
    assert (smoke.LINUX_FALLBACK_FIELD in setup_form) is expects_consent
    assert calls[1][2] in known_secrets
    assert [call[0] for call in calls] == [
        "/unlock",
        "/unlock",
        "/unlock/2fa/setup",
        "/session/new",
    ]


@pytest.mark.parametrize(
    ("failed_stage", "expected_message"),
    [
        ("setup", "Device setup did not reach optional 2FA setup"),
        ("skip", "Optional 2FA setup did not complete"),
        ("session", "ML-KEM session creation did not complete"),
    ],
)
def test_packaged_flow_still_fails_when_required_stage_does_not_complete(
    failed_stage,
    expected_message,
):
    smoke = load_smoke_module()
    csrf = "csrf-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    browser = "browser-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    bootstrap = "bootstrap-fixture-abcdefghijklmnopqrstuvwxyz1234567890"

    def request(path, form=None, request_csrf=None):
        if path == "/unlock" and form is None:
            return FakeResponse(
                "http://127.0.0.1:54321/unlock",
                unlock_html(csrf, offers_linux_fallback=True),
            )
        if path == "/unlock":
            final_path = "/unlock" if failed_stage == "setup" else "/unlock/2fa/setup"
        elif path == "/unlock/2fa/setup":
            final_path = "/unlock" if failed_stage == "skip" else "/"
        elif path == "/session/new":
            final_path = "/session/new" if failed_stage == "session" else f"/session/{'a' * 32}"
        else:
            raise AssertionError(f"Unexpected request path: {path}")
        body = (
            f'<meta name="paracci-browser-token" content="{browser}">'
            f'<meta name="paracci-csrf-token" content="{csrf}">'
        )
        return FakeResponse(
            f"http://127.0.0.1:54321{final_path}?bootstrap_token={bootstrap}",
            body,
        )

    def fail(message):
        raise smoke.SmokeFailure(message)

    with pytest.raises(smoke.SmokeFailure, match=expected_message) as failure:
        smoke.complete_authenticated_flow(
            "linux",
            request,
            fail,
            known_secrets=[bootstrap],
        )

    failure_text = str(failure.value)
    assert csrf not in failure_text
    assert browser not in failure_text
    assert bootstrap not in failure_text
    assert "<redacted>" in failure_text


def test_failure_output_redacts_tokens_headers_cookies_secrets_and_local_paths(tmp_path):
    smoke = load_smoke_module()
    repo_root = tmp_path / "repo"
    data_root = tmp_path / "isolated-data"
    executable = repo_root / "builds" / "linux" / "Paracci" / "Paracci"
    unlabeled = "unlabeled-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    csrf = "csrf-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    browser = "browser-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    bearer = "bearer-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    bootstrap = "bootstrap-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    native_save = "native-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    preview = "preview-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    cookie = "cookie-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    windows_path = "\\".join(["C:", "Users", "private-user", "Desktop", "paracci-msg", "trace.log"])
    unc_path = "\\\\" + "\\".join(["private-server", "share", "paracci", "trace.log"])
    linux_path = "/" + "/".join(["home", "private-user", ".cache", "paracci", "trace.log"])
    workspace_path = "/" + "/".join(["workspace", "paracci-msg", "trace.log"])
    foreign_data_dir = "/" + "/".join(["custom-data-root", "private", "data"])

    message = "\n".join(
        [
            f'<meta name="paracci-csrf-token" content="{csrf}">',
            f'<meta content="{browser}" name="paracci-browser-token">',
            f'<input name="native_save_token" value="{native_save}">',
            f'{{"bearer_token": "{bearer}", "preview_token": "{preview}"}}',
            f"url=http://127.0.0.1:54321/__paracci_bootstrap?token={bootstrap}&next=/unlock",
            f"preview=http://127.0.0.1:54321/preview/{preview}",
            f"authorization: Bearer {bearer}",
            f"cookie: session={cookie}",
            f"set-cookie: session={cookie}",
            f"X-Paracci-Token: {bearer}",
            f"native_save_token={native_save}&preview_token={preview}",
            f"native-save-token={native_save}",
            f"DATA_DIR={foreign_data_dir}",
            f"repo={repo_root}",
            f"executable={executable}",
            f"windows={windows_path}",
            f"unc={unc_path}",
            f"linux={linux_path}",
            f"workspace={workspace_path}",
            f"passphrase={smoke.SMOKE_PIN}",
            f"exception contained {unlabeled}",
        ]
    )
    output = f"subprocess output: {message}"

    redacted = smoke.format_failure_message(
        message,
        output,
        known_secrets=[unlabeled],
        roots=[repo_root, data_root, executable],
    )

    for sensitive in (
        csrf,
        browser,
        bearer,
        bootstrap,
        native_save,
        preview,
        cookie,
        unlabeled,
        smoke.SMOKE_PIN,
        str(repo_root),
        str(data_root),
        str(executable),
        windows_path,
        unc_path,
        linux_path,
        workspace_path,
        foreign_data_dir,
    ):
        assert sensitive not in redacted
    assert "<redacted>" in redacted
    assert "<local-path>" in redacted
    assert "/unlock" in redacted


def test_response_body_is_redacted_before_failure_snippet_is_truncated():
    smoke = load_smoke_module()
    browser = "browser-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    body = "A" * 995 + f'<meta name="paracci-browser-token" content="{browser}">'

    message = smoke.response_failure_message(
        "Session failed.",
        "http://127.0.0.1:54321/unlock",
        body,
    )

    assert browser not in message
    assert len(message.split("Body: ", 1)[1]) <= 1000


def test_missing_executable_failure_redacts_local_path(tmp_path):
    smoke = load_smoke_module()
    missing = tmp_path / "private-build" / "Paracci"

    with pytest.raises(smoke.SmokeFailure) as failure:
        smoke.smoke_packaged_runtime(missing, "linux")

    assert str(missing) not in str(failure.value)
    assert "<local-path>" in str(failure.value)


def test_main_redacts_unexpected_exception_summary(tmp_path, monkeypatch, capsys):
    smoke = load_smoke_module()
    secret = "bootstrap-fixture-abcdefghijklmnopqrstuvwxyz1234567890"
    repo_root = tmp_path / "private-repo"
    executable = repo_root / "builds" / "linux" / "Paracci" / "Paracci"

    def fail_unexpected(*_args, **_kwargs):
        raise RuntimeError(f"token={secret} DATA_DIR={repo_root}")

    monkeypatch.setattr(smoke, "smoke_packaged_runtime", fail_unexpected)

    result = smoke.main(
        [
            "--platform",
            "linux",
            "--repo-root",
            str(repo_root),
            "--executable",
            str(executable),
        ]
    )

    error = capsys.readouterr().err
    assert result == 1
    assert secret not in error
    assert str(repo_root) not in error
    assert "token=<redacted>" in error
    assert "<local-path>" in error
