#!/bin/bash
set -euo pipefail

CFG=/etc/osmocom/osmo-sgsn.cfg
TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Remove any previous api lines
grep -vE '^ api (listen-ip|port|token) ' "$CFG" > "${CFG}.tmp"
mv "${CFG}.tmp" "$CFG"

# Insert api lines inside sgsn block (before cs7-instance-iu line if present, else at end)
if grep -q ' cs7-instance-iu ' "$CFG"; then
  sed -i "/ cs7-instance-iu /i\\ api listen-ip 0.0.0.0\\n api port 8088\\n api token ${TOKEN}" "$CFG"
else
  cat >> "$CFG" <<EOF
 api listen-ip 0.0.0.0
 api port 8088
 api token ${TOKEN}
EOF
fi

# Test config parse (timeout after 2s if starts successfully)
if ! timeout 2 /usr/bin/osmo-sgsn -c "$CFG" >/tmp/sgsn-test.log 2>&1; then
  if grep -q 'cs7 instance' /tmp/sgsn-test.log; then
    echo "REBUILD: cs7 not supported in current binary, rebuilding with --enable-iu"
    cd /opt/osmo-sgsn
    ./configure --enable-iu --prefix=/usr
    make -j"$(nproc)"
    make install
  else
    cat /tmp/sgsn-test.log
    exit 1
  fi
fi

systemctl reset-failed osmo-sgsn || true
systemctl restart osmo-sgsn
sleep 3

echo "SERVICE=$(systemctl is-active osmo-sgsn)"
echo "API_TOKEN=set"
curl -s http://127.0.0.1:8088/health || true
echo
curl -s -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:8088/v1/contexts/counts || true
echo
