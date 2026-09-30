#!/usr/bin/env bash
# Launch the local API (binds 127.0.0.1 only by default).
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8000
