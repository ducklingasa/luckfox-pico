#!/bin/bash
# pivpn backup: archive /userdata/wireguard and /etc/pivpn, keep the last 5

. /opt/pivpn/common.sh

KEEP=5
BACKUP_DIR=${BACKUP_DIR:-/userdata/vpn-backup}
WGDATA=$(readlink -f "$WGDIR")

umask 077
take_lock
require_server

mkdir -p "$BACKUP_DIR" || die "Cannot create $BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

file=$BACKUP_DIR/pivpnbackup-$(date +%Y%m%d-%H%M%S).tgz
# BusyBox tar has no gzip support, so compress in a pipe
if ! tar -C / -cf - "${WGDATA#/}" etc/pivpn | gzip -c >"$file"; then
	rm -f "$file"
	die "Backup failed"
fi
chmod 0600 "$file"

# Keep only the newest $KEEP archives (names sort by timestamp)
ls -1 "$BACKUP_DIR"/pivpnbackup-*.tgz 2>/dev/null | sort -r | awk -v k=$KEEP 'NR > k' | while read -r old; do
	rm -f "$old"
done

ip=$(ip -4 -o addr show "${IPv4dev:-eth0}" 2>/dev/null | awk '{ split($4, a, "/"); print a[1]; exit }')
echo "::: Backup created: $file"
echo "::: Copy it off the device, e.g.:"
echo "    scp root@${ip:-<device-ip>}:$file ."
