#!/bin/bash
# Ensure Gn policy + API lines in osmo-sgsn.cfg have valid VTY indentation.
# Preserves the existing API token unless none is set.
set -euo pipefail

CFG=/etc/osmocom/osmo-sgsn.cfg
WORKDIR=/var/lib/osmocom
IP=127.0.0.1
GN_IU_RELEASE=" iu-release-pdp-action delete-gn"
GN_RNC_LOSS=" rnc-loss-pdp-action delete-gn"
GN_UNREACHABLE=" unreachable-pdp-timer 3600"

TOKEN=$(grep '^ api token ' "$CFG" 2>/dev/null | awk '{print $4}' || true)
if [ -z "${TOKEN:-}" ]; then
	TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
fi

grep -vE '^[[:space:]]*(api |iu-release-pdp-action|rnc-loss-pdp-action|unreachable-pdp-timer)' "$CFG" > "$WORKDIR/cfg.gnfix"

awk -v iu="$GN_IU_RELEASE" -v rnc="$GN_RNC_LOSS" -v unreach="$GN_UNREACHABLE" '
	/ cs7-instance-iu / && !done {
		print iu
		print rnc
		print unreach
		done = 1
	}
	{ print }
	END {
		if (!done) {
			print iu
			print rnc
			print unreach
		}
	}
' "$WORKDIR/cfg.gnfix" > "$WORKDIR/cfg.gnfix2"

{
	cat "$WORKDIR/cfg.gnfix2"
	echo " api bind ${IP} 8088"
	echo " api token ${TOKEN}"
} > "$WORKDIR/cfg.final"

cp "$WORKDIR/cfg.final" "$CFG"
chown osmocom:osmocom "$CFG"

for want in "$GN_IU_RELEASE" "$GN_RNC_LOSS" "$GN_UNREACHABLE"; do
	if ! grep -qxF "$want" "$CFG"; then
		echo "CONFIG_VALIDATE=failed (missing: $want)"
		exit 1
	fi
done

echo "CONFIG_VALIDATE=ok"
echo "API_TOKEN=set"
grep -E 'iu-release-pdp-action|rnc-loss-pdp-action|unreachable-pdp-timer|^ api ' "$CFG"
