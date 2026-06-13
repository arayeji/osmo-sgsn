#!/bin/bash
# Build and install osmo-sgsn on Ubuntu/Debian (run as root).
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/arayeji/osmo-sgsn.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/osmo-sgsn}"
BRANCH="${BRANCH:-master}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash contrib/server-install.sh"
  exit 1
fi

bash "$SCRIPT_DIR/wsl-setup-osmo-deps.sh"

if [[ -d "$ROOT/.git" ]]; then
  SRC="$ROOT"
  echo "Using existing checkout at $SRC"
else
  SRC="$INSTALL_DIR"
  rm -rf "$SRC"
  git clone --branch "$BRANCH" "$REPO_URL" "$SRC"
fi

cd "$SRC"
if [[ ! -f configure ]]; then
  autoreconf -fi
fi
if [[ ! -f Makefile ]]; then
  ./configure --disable-iu --prefix=/usr
fi

make -j"$(nproc)"
make install

echo "Installed: $(command -v osmo-sgsn)"
osmo-sgsn --version 2>/dev/null || true
echo "Configure HTTP API in osmo-sgsn.cfg: api listen-ip, api port, api token"
