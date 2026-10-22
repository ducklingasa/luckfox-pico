#!/bin/bash
# pivpn clients: live status of the connected peers

. /opt/pivpn/common.sh

require_server
wg_running || die "$pivpnDEV is not running"

declare -A names
while read -r name pub _; do
	[ -n "$name" ] && names[$pub]=$name
done <"$CLIENTS"

printf '\e[1m%-15s  %-21s  %-15s  %-10s  %-10s  %-20s\e[0m\n' "Name" "Remote IP" "Virtual IP" "Bytes RX" "Bytes TX" "Last seen"

# wg show dump: first line is the interface, then one line per peer:
# pubkey psk endpoint allowed-ips latest-handshake rx tx keepalive
wg show "$pivpnDEV" dump | awk 'NR > 1' | while read -r pub _ endpoint allowed handshake rx tx _; do
	name=${names[$pub]:-"(unknown)"}
	[ "$endpoint" = "(none)" ] && endpoint="-"
	if [ "$handshake" -eq 0 ]; then
		seen="(not yet)"
	else
		seen=$(fmt_date "$handshake")
	fi
	printf '%-15s  %-21s  %-15s  %-10s  %-10s  %-20s\n' \
		"$name" "$endpoint" "${allowed%%/*}" "$(human_bytes "$rx")" "$(human_bytes "$tx")" "$seen"
done

disabled=$(grep -cF "${DISABLED_PREFIX}### begin " "$WGCONF")
[ "$disabled" -gt 0 ] && echo "::: $disabled disabled client(s) not shown, see 'pivpn list'"
exit 0
