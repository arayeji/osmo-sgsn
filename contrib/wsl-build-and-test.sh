#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! pkg-config --exists 'libosmocore >= 1.10.0' 2>/dev/null; then
  echo "Osmocom deps missing or too old. Run as root: bash contrib/wsl-setup-osmo-deps.sh"
  exit 1
fi

if ! python3 -c "import osmopy" 2>/dev/null; then
  echo "python3-osmopy-utils missing. Run as root: bash contrib/wsl-setup-osmo-deps.sh"
  exit 1
fi

if [[ ! -f configure ]]; then
  autoreconf -fi
fi

if [[ ! -f Makefile ]]; then
  ./configure --disable-iu
fi

make -j"$(nproc)"

echo "=== Running CTRL tests ==="
make -C tests ctrl-python-test

echo "=== Running VTY tests ==="
make -C tests vty-python-test

echo "=== Build and unit tests OK ==="
