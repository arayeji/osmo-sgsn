#!/bin/bash
cd /var/lib/osmocom
BASE="$PWD/base.cfg"
grep -v '^ api ' /etc/osmocom/osmo-sgsn.cfg > "$BASE"

run() {
  echo "=== $1 ==="
  timeout 2 /usr/bin/osmo-sgsn -c "$2" >"$PWD/out.log" 2>&1 && echo OK || echo FAIL
  grep -E 'libGTP|HTTP API|Error|below line' "$PWD/out.log" | head -3
}

cp "$BASE" "$PWD/t-bind.cfg"
echo " api bind 127.0.0.1 8088" >> "$PWD/t-bind.cfg"
run bind-only "$PWD/t-bind.cfg"

cp "$BASE" "$PWD/t-both.cfg"
cat >> "$PWD/t-both.cfg" <<'EOF'
 api bind 127.0.0.1 8088
 api token abc123
EOF
run bind-token "$PWD/t-both.cfg"
