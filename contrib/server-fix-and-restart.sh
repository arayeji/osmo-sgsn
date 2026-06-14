#!/bin/bash
# Reinstall fork binary, fix Gn config, drop stale copies, hold apt package.
set -euo pipefail

REPO=/opt/osmo-sgsn
cd "$REPO"

git config --global --add safe.directory "$REPO" 2>/dev/null || true
git fetch origin master
git reset --hard origin/master

./configure --enable-iu --prefix=/usr
make -j"$(nproc)"
make install

rm -f /usr/local/bin/osmo-sgsn

# Prevent nightly apt from overwriting our custom /usr/bin/osmo-sgsn
apt-mark hold osmo-sgsn 2>/dev/null || true

bash "$REPO/contrib/server-fix-gn-config.sh"

systemctl daemon-reload
systemctl reset-failed osmo-sgsn || true
systemctl restart osmo-sgsn
sleep 5

echo "SERVICE=$(systemctl is-active osmo-sgsn)"
echo "BINARY=$(readlink -f "$(which osmo-sgsn)")"
strings /usr/bin/osmo-sgsn | grep -E 'unreachable-pdp-timer|iu-release-pdp-action' | head -3
curl -s "http://127.0.0.1:8088/health" || true
echo
TOKEN=$(grep '^ api token ' /etc/osmocom/osmo-sgsn.cfg | awk '{print $4}')
curl -s -H "Authorization: Bearer ${TOKEN}" "http://127.0.0.1:8088/v1/contexts/counts" || true
echo
