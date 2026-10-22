#!/bin/bash
# pivpn qrcode [name]: show a client config as QR code

. /opt/pivpn/common.sh

require_server
command -v qrencode >/dev/null 2>&1 || die "qrencode is not installed"

name=$1
[ -n "$name" ] || name=$(prompt_client)
valid_name "$name" || die "Invalid name '$name'"
[ -f "$CONFDIR/${name}.conf" ] || die "No config for client '$name'"

echo "::: Client config for '$name' (scan with the WireGuard app):"
qrencode -t ansiutf8 <"$CONFDIR/${name}.conf"
