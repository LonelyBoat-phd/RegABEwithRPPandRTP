#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
regabe_python="${REGABE_PYTHON:-python3}"
"$regabe_python" -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12 or newer is required"'
"$regabe_python" tools/check_integrity.py
"$regabe_python" -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tools/build_native.py
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m unittest discover -s supplement/tests -v
echo 'Ready. Run: .venv/bin/python example.py'
