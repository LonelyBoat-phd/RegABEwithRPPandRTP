#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ -n "${REGABE_PYTHON:-}" ]]; then
  regabe_python="$REGABE_PYTHON"
elif [[ -x .venv/bin/python ]]; then
  regabe_python=.venv/bin/python
else
  python3 -m venv .venv
  regabe_python=.venv/bin/python
fi
"$regabe_python" -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12 or newer is required"'
"$regabe_python" tools/check_integrity.py
if ! "$regabe_python" -c 'import cffi, cryptography, scipy, matplotlib; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey; assert hasattr(Ed25519PublicKey, "public_bytes_raw")' >/dev/null 2>&1; then
  "$regabe_python" -m pip install -r supplement/requirements.txt
fi
# Source-only releases build the bridge on their first run. Rebuild when the
# bridge, build recipe or vendored PBC archive changes; no stale binary fallback.
if [[ ! -f native/libregabe_type1.so || native/type1.c -nt native/libregabe_type1.so || tools/build_native.py -nt native/libregabe_type1.so || vendor/pbc-0.5.14.tar.gz -nt native/libregabe_type1.so ]]; then
  "$regabe_python" tools/build_native.py
fi
"$regabe_python" -c 'import regabe'
"$regabe_python" -m unittest discover -s supplement/tests -v
"$regabe_python" -u -m supplement.run "$@"
