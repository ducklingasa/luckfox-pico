#!/bin/bash
# pivpn backup: archive /userdata/wireguard and /etc/pivpn, keep the last 5

. /opt/pivpn/common.sh
set -o pipefail

web=0
case "${1:-}" in
	"") ;;
	--web) web=1 ;;
	*) die "Usage: pivpn backup [--web]" ;;
esac

KEEP=5
BACKUP_DIR=${BACKUP_DIR:-/userdata/vpn-backup}
WGDATA=$(readlink -f "$WGDIR")

umask 077
take_lock
require_server

mkdir -p "$BACKUP_DIR" || die "Cannot create $BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

base=$BACKUP_DIR/pivpnbackup-$(date +%Y%m%d-%H%M%S)
file=$base.tgz
i=0
while [ -e "$file" ]; do
	i=$((i + 1))
	file=$base-$i.tgz
done
tmp=$(mktemp "$BACKUP_DIR/.backup.XXXXXX") || die "Cannot create temporary backup"
trap 'rm -f "$tmp"' EXIT
# BusyBox tar has no gzip support, so compress in a pipe
if ! tar -C / -cf - "${WGDATA#/}" etc/pivpn | gzip -c >"$tmp"; then
	die "Backup failed"
fi
chmod 0600 "$tmp" || die "Cannot protect backup"
mv "$tmp" "$file" || die "Cannot publish backup"

# Use modification time, not lexical suffix order (10 sorts before 2).
python3 -I /opt/pivpn/prune-backups.py "$BACKUP_DIR" "$KEEP" "$file" ||
	die "Backup created but retention cleanup failed"

if [ "$web" -eq 1 ]; then
	basename "$file"
	exit 0
fi

ip=$(ip -4 -o addr show "${IPv4dev:-eth0}" 2>/dev/null | awk '{ split($4, a, "/"); print a[1]; exit }')
echo "::: Backup created: $file"
echo "::: Copy it off the device, e.g.:"
echo "    scp root@${ip:-<device-ip>}:$file ."
