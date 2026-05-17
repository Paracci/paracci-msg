"""Stdio JSON-RPC worker for the macOS SwiftUI frontend.

The worker uses only stdin/stdout transport. It reads one JSON object per line
from stdin and writes one JSON response per line to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from desktop.services import NativeServices, configure_data_dir
from ui_api import UIApi, UIApiError


def make_response(request_id: Any, ok: bool, result: dict | None = None, error: dict | None = None) -> dict:
    response = {"id": request_id, "ok": ok}
    if ok:
        response["result"] = result or {}
    else:
        response["error"] = error or {"code": "unknown_error", "message": "Unknown error", "details": None}
    return response


def handle_line(api: UIApi, line: str) -> dict:
    try:
        request = json.loads(line)
    except json.JSONDecodeError as exc:
        return make_response(None, False, error={"code": "invalid_json", "message": str(exc), "details": None})

    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    if not isinstance(method, str):
        return make_response(
            request_id,
            False,
            error={"code": "invalid_request", "message": "Request method must be a string.", "details": None},
        )
    if not isinstance(params, dict):
        return make_response(
            request_id,
            False,
            error={"code": "invalid_request", "message": "Request params must be an object.", "details": None},
        )

    try:
        return make_response(request_id, True, result=api.dispatch(method, params))
    except UIApiError as exc:
        return make_response(request_id, False, error=exc.to_dict())
    except Exception as exc:
        return make_response(
            request_id,
            False,
            error={"code": exc.__class__.__name__, "message": str(exc), "details": None},
        )


def run_worker(data_dir: str | None = None, user_profile: str | None = None, locale: str = "en") -> int:
    selected_data_dir = configure_data_dir(data_dir, user_profile)
    services = NativeServices(selected_data_dir, locale)
    api = UIApi(services)

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        response = handle_line(api, line)
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Paracci stdio JSON-RPC worker")
    parser.add_argument("--data-dir", help="Explicit data directory")
    parser.add_argument("--user", choices=["x", "y"], help="Development profile selector")
    parser.add_argument("--locale", default=os.environ.get("PARACCI_LOCALE", "en"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    return run_worker(args.data_dir, args.user, args.locale)


if __name__ == "__main__":
    raise SystemExit(main())
