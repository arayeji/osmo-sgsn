#!/bin/bash
set -euo pipefail
cd /opt/osmo-sgsn
git fetch origin master
git reset --hard origin/master
./configure --enable-iu --prefix=/usr
make -j"$(nproc)"
make install
systemctl reset-failed osmo-sgsn || true
systemctl restart osmo-sgsn
sleep 4
echo "SERVICE=$(systemctl is-active osmo-sgsn)"
TOKEN=$(grep '^ api token ' /etc/osmocom/osmo-sgsn.cfg | awk '{print $4}')
echo "API_TOKEN=set"
curl -s http://127.0.0.1:8088/health || true
echo
curl -s -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:8088/v1/contexts/counts || true
echo
