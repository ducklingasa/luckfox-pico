#!/bin/sh
umask 077
exec 8>/run/webui/request.lock || exit 1
for attempt in 1 2 3 4 5; do
	if flock -n 8; then
		exec /usr/bin/python3 -I -B /opt/vpn-web/webui.py
	fi
	sleep 0.1
done
printf 'Status: 503\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n'
printf '{"ok":false,"error":{"code":"busy","message":"Another web request is running. Please retry."}}'
