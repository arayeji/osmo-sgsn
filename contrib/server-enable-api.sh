#!/bin/bash
set -euo pipefail

CFG=/etc/osmocom/osmo-sgsn.cfg
TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

grep -vE '^ api (listen-ip|port|token) ' "$CFG" > "${CFG}.tmp" || true
mv "${CFG}.tmp" "$CFG"
cat >> "$CFG" <<EOF
 api listen-ip 0.0.0.0
 api port 8088
 api token ${TOKEN}
EOF

systemctl restart osmo-sgsn
sleep 3
echo "SERVICE=$(systemctl is-active osmo-sgsn)"
echo "API_TOKEN=set"
curl -s http://127.0.0.1:8088/health || true
echo
curl -s -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:8088/v1/contexts/counts || true
echo
