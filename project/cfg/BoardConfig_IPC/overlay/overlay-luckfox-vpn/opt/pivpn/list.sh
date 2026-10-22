#!/bin/bash
# pivpn list: show all clients from clients.txt

. /opt/pivpn/common.sh

require_server

if [ ! -s "$CLIENTS" ]; then
	echo "::: There are no clients"
	exit 0
fi

printf '\e[1m%-15s  %-44s  %-20s  %-15s\e[0m\n' "Client" "Public key" "Creation date" "Virtual IP"
while read -r name pub epoch ip; do
	[ -n "$name" ] || continue
	flag=""
	client_state "$name"
	[ $? -eq 1 ] && flag=" [disabled]"
	printf '%-15s  %-44s  %-20s  %-15s%s\n' "$name" "$pub" "$(fmt_date "$epoch")" "$ip" "$flag"
done <"$CLIENTS"
