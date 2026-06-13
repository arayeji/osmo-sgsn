#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_DIR="$ROOT/contrib/osmo-sgsn-api"
SGSN_BIN="$ROOT/src/sgsn/osmo-sgsn"
CFG="$ROOT/tests/osmo-sgsn-accept-all.cfg"
TOKEN="test-token-wsl"
PORT=18088

if [[ ! -x "$SGSN_BIN" ]]; then
  echo "osmo-sgsn not built at $SGSN_BIN"
  exit 1
fi

pkill -f 'src/sgsn/osmo-sgsn' 2>/dev/null || true
pkill -f 'osmo_sgsn_api' 2>/dev/null || true
sleep 1

export OSMO_SGSN_API_TOKEN="$TOKEN"
export OSMO_SGSN_VTY_HOST=127.0.0.1
export OSMO_SGSN_VTY_PORT=4245
export OSMO_SGSN_API_HOST=127.0.0.1
export OSMO_SGSN_API_PORT="$PORT"

"$SGSN_BIN" -c "$CFG" &
SGSN_PID=$!
sleep 2

cleanup() {
  if [[ -n "${API_PID:-}" ]]; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  kill "$SGSN_PID" 2>/dev/null || true
  wait "$SGSN_PID" 2>/dev/null || true
}
trap cleanup EXIT

VENV_DIR="${TMPDIR:-/tmp}/osmo-sgsn-api-venv"
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q -r "$API_DIR/requirements.txt"
fi

cd "$API_DIR"
API_PID=$(
  "$VENV_DIR/bin/python" run.py &
  echo $!
)
cd "$ROOT"
sleep 3

echo "=== API health ==="
curl -sf --max-time 5 "http://127.0.0.1:${PORT}/health"
echo ""

echo "=== API counts (auth) ==="
curl -sf --max-time 10 -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:${PORT}/v1/contexts/counts"
echo ""

echo "=== VTY detach commands exist ==="
python3 <<'PY'
import socket, time, re
s = socket.create_connection(("127.0.0.1", 4245), timeout=5)
buf = b""
deadline = time.time() + 10
while time.time() < deadline:
    buf += s.recv(4096)
    if re.search(rb"OsmoSGSN[#>]\s*$", buf):
        break
s.sendall(b"enable\n")
buf = b""
deadline = time.time() + 10
while time.time() < deadline:
    buf += s.recv(4096)
    if re.search(rb"OsmoSGSN#\s*$", buf):
        break
s.sendall(b"list\n")
buf = b""
deadline = time.time() + 10
while time.time() < deadline:
    buf += s.recv(65536)
    if re.search(rb"OsmoSGSN#\s*$", buf):
        break
text = buf.decode()
assert "subscriber imsi IMSI disconnect" in text
assert "subscriber imsi IMSI detach" in text
print("VTY commands OK")
PY

echo "=== API integration test OK ==="
