#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  python3 -m venv .venv
fi
"$ROOT/.venv/bin/python" -m pip install -U pip
"$ROOT/.venv/bin/python" -m pip install -e .
if [[ ! -f "$ROOT/config.yaml" ]]; then
  cp config.example.yaml config.yaml
fi
exec "$ROOT/.venv/bin/python" -m campus_connect setup
