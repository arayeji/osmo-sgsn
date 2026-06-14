#!/bin/bash
set -euo pipefail
cd /opt/osmo-sgsn
bash contrib/server-fix-gn-config.sh

systemctl reset-failed osmo-sgsn || true
systemctl restart osmo-sgsn
sleep 5

IP=127.0.0.1
TOKEN=$(grep '^ api token ' /etc/osmocom/osmo-sgsn.cfg | awk '{print $4}')

echo "SERVICE=$(systemctl is-active osmo-sgsn)"
echo "API_TOKEN=set"
curl -s "http://${IP}:8088/health" || true
echo
curl -s -H "Authorization: Bearer ${TOKEN}" "http://${IP}:8088/v1/contexts/counts" || true
echo
