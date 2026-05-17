#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
swift build
swift run ParacciMac
