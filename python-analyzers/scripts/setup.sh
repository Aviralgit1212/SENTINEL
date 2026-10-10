#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BOOTSTRAP:-python3}"
VENV="$ROOT/.venv"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: Python 3 is required (set PYTHON_BOOTSTRAP to its executable)." >&2
  exit 2
fi
"$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'
"$PYTHON_BIN" -m venv "$VENV"
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_DEFAULT_TIMEOUT=15 "$VENV/bin/python" -m pip install --retries 1 -r "$ROOT/requirements.txt"
"$VENV/bin/python" -c 'import pymupdf; print("PyMuPDF", pymupdf.VersionBind, "ready")'
echo "Python analyzer environment ready: $VENV"
echo "The server auto-discovers this environment; alternatively set PYTHON_EXECUTABLE=$VENV/bin/python."
