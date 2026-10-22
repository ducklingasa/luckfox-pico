#!/bin/bash
# pivpn restore <file.tgz> [-y]: restore an archive created by 'pivpn backup'

. /opt/pivpn/common.sh

WGDATA=/userdata/wireguard

file=""
yes=0
while [ $# -gt 0 ]; do
	case "$1" in
		-y | --yes) yes=1 ;;
		-h | --help)
			echo "Usage: pivpn restore <pivpnbackup-*.tgz> [-y]"
			exit 0
			;;
		-*) die "Unknown option: $1" ;;
		*) file=$1 ;;
	esac
	shift
done

[ -n "$file" ] || die "Usage: pivpn restore <pivpnbackup-*.tgz> [-y]"
[ -f "$file" ] || die "$file not found"

# Only accept archives that contain nothing but our two trees
entries=$(gzip -dc "$file" | tar -tf -) || die "$file is not a valid .tgz archive"
while IFS= read -r e; do
	e=${e#./}
	case "$e" in
		*..*) die "Refusing archive: suspicious path '$e'" ;;
		userdata/wireguard | userdata/wireguard/* | etc/pivpn | etc/pivpn/*) ;;
		*) die "Refusing archive: unexpected path '$e'" ;;
	esac
done <<<"$entries"
grep -qxE "(\./)?userdata/wireguard/${pivpnDEV}\.conf" <<<"$entries" ||
	die "Archive does not contain userdata/wireguard/$pivpnDEV.conf"

if [ $yes -eq 0 ]; then
	echo "::: This replaces the current server keys, clients and settings with the contents of"
	echo ":::   $file"
	confirm "Continue?" || exit 1
fi

umask 077
take_lock

tmp=$(mktemp -d /userdata/.pivpn-restore.XXXXXX) || die "mktemp failed"
trap 'rm -rf "$tmp"' EXIT
gzip -dc "$file" | tar -C "$tmp" -xf - || die "Extraction failed"
[ -f "$tmp/userdata/wireguard/$pivpnDEV.conf" ] || die "Extracted archive has no $pivpnDEV.conf"

if wg_running; then
	wg-quick down "$pivpnDEV" || die "wg-quick down failed"
fi

# Keep the previous state once, in case the restore was a mistake
rm -rf "$WGDATA.prev"
[ -d "$WGDATA" ] && mv "$WGDATA" "$WGDATA.prev"
mv "$tmp/userdata/wireguard" "$WGDATA" || die "Could not move restored data into place"

if [ -d "$tmp/etc/pivpn" ]; then
	mkdir -p /etc/pivpn
	cp -a "$tmp/etc/pivpn/." /etc/pivpn/
	chmod -R u=rwX,go=rX /etc/pivpn
fi

chown -R root:root "$WGDATA"
# directories 0700, files 0600
chmod -R u=rwX,go= "$WGDATA"
find "$WGDATA" -type f | while IFS= read -r f; do chmod 0600 "$f"; done

ln -sfn "$WGDATA" "$WGDIR"

. "$SETUPVARS"
wg-quick up "$pivpnDEV" || die "wg-quick up failed; previous data is in $WGDATA.prev"

echo "::: Restore complete. Previous data kept in $WGDATA.prev"
