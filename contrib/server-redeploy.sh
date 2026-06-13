#!/bin/bash
set -euo pipefail
cd /opt/osmo-sgsn
git fetch origin master
git reset --hard origin/master
./configure --enable-iu --prefix=/usr
make -j"$(nproc)"
make install
bash contrib/server-final-enable-api.sh
