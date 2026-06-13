#!/bin/bash
set -euo pipefail

REPO=/opt/osmo-sgsn
CFG=/etc/osmocom/osmo-sgsn.cfg

cd "$REPO"
git fetch origin master
git reset --hard origin/master

bash contrib/wsl-setup-osmo-deps.sh
bash contrib/server-install.sh

# Ensure API is configured
if ! grep -q '^ api token ' "$CFG"; then
  TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  grep -vE '^ api (listen-ip|port|token) ' "$CFG" > "${CFG}.tmp"
  mv "${CFG}.tmp" "$CFG"
  if grep -q ' cs7-instance-iu ' "$CFG"; then
    sed -i "/ cs7-instance-iu /i\\ api listen-ip 0.0.0.0\\n api port 8088\\n api token ${TOKEN}" "$CFG"
  else
    cat >> "$CFG" <<EOF
 api listen-ip 0.0.0.0
 api port 8088
 api token ${TOKEN}
EOF
  fi
else
  TOKEN=$(grep '^ api token ' "$CFG" | awk '{print $4}')
fi

rm -f /usr/local/bin/osmo-sgsn
systemctl daemon-reload
systemctl reset-failed osmo-sgsn || true
systemctl restart osmo-sgsn
sleep 4

echo "SERVICE=$(systemctl is-active osmo-sgsn)"
echo "API_TOKEN=set"
curl -s http://127.0.0.1:8088/health || true
echo
curl -s -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:8088/v1/contexts/counts || true
echo
