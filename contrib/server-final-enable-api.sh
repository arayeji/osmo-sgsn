#!/bin/bash
set -euo pipefail
WORKDIR=/var/lib/osmocom
CFG=/etc/osmocom/osmo-sgsn.cfg
TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
IP=127.0.0.1

grep -vE '^ api |^ iu-release-pdp-action |^ rnc-loss-pdp-action |^ unreachable-pdp-timer ' "$CFG" > "$WORKDIR/cfg.new"

if grep -q ' cs7-instance-iu ' "$WORKDIR/cfg.new"; then
	sed -i '/ cs7-instance-iu /i iu-release-pdp-action delete-gn\n rnc-loss-pdp-action delete-gn' "$WORKDIR/cfg.new"
else
	cat >> "$WORKDIR/cfg.new" <<'GNCFG'
 iu-release-pdp-action delete-gn
 rnc-loss-pdp-action delete-gn
GNCFG
fi

cat >> "$WORKDIR/cfg.new" <<EOF
 api bind ${IP} 8088
 api token ${TOKEN}
EOF
cp "$WORKDIR/cfg.new" "$CFG"
chown osmocom:osmocom "$CFG"

systemctl reset-failed osmo-sgsn || true
systemctl restart osmo-sgsn
sleep 5

echo "SERVICE=$(systemctl is-active osmo-sgsn)"
echo "API_TOKEN=set"
grep -E 'iu-release-pdp-action|rnc-loss-pdp-action|unreachable-pdp-timer' "$CFG" || true
curl -s "http://${IP}:8088/health" || true
echo
curl -s -H "Authorization: Bearer ${TOKEN}" "http://${IP}:8088/v1/contexts/counts" || true
echo
