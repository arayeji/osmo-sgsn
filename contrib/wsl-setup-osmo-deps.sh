#!/bin/bash
set -euo pipefail

OSMOCOM_REPO="https://downloads.osmocom.org/packages/osmocom:/nightly/xUbuntu_24.04"

apt-get update -qq
apt-get install -y -qq wget gpg libc-ares-dev

mkdir -p /etc/apt/keyrings
wget -q "${OSMOCOM_REPO}/Release.key" -O /tmp/osmocom-nightly.key
gpg --dearmor < /tmp/osmocom-nightly.key > /etc/apt/keyrings/osmocom-nightly.gpg

cat > /etc/apt/sources.list.d/osmocom-nightly.list <<EOF
deb [signed-by=/etc/apt/keyrings/osmocom-nightly.gpg] ${OSMOCOM_REPO}/ ./
EOF

apt-get update -qq
apt-get install -y \
  build-essential autoconf automake libtool pkg-config \
  python3 python3-pip python3-venv python3-osmopy-utils \
  libosmocore-dev libosmo-gsup-client-dev libosmo-abis-dev libgtp-dev libosmo-netif-dev

pkg-config --modversion libosmocore libgtp libosmogsm libosmogb libosmovty
