#!/bin/bash
set -eu

R=${RK_PROJECT_PACKAGE_ROOTFS_DIR:?rootfs directory is required}
[ -d "$R/var/www" ] && [ -f "$R/opt/vpn-web/vpn-native" ] ||
	{ echo "luckfox-vpn-overlay-post: native CGI missing from assembled rootfs" >&2; exit 1; }
mkdir -p "$R/var/www/cgi-bin"
chmod 0755 "$R/opt/vpn-web/vpn-native" "$R/etc/init.d/S49httpd"
# Remove obsolete deployment files from incremental assembled rootfs trees.
rm -f "$R/etc/vpn-web-backend" "$R/opt/vpn-web/select-backend" \
	"$R/opt/vpn-web/vpn-legacy.cgi"
ln -sfn /opt/vpn-web/vpn-native "$R/var/www/cgi-bin/vpn.cgi"

# The SDK's static formatter bypasses fakeroot; use the dynamic host formatter
# so ownership and image population share the same emulated metadata.
if [ "${1-}" = --image ]; then
	shift
	RK_MKFS_EXT4=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v mkfs.ext4) ||
		{ echo "luckfox-vpn-overlay-post: host mkfs.ext4 is required" >&2; exit 1; }
	ldd "$RK_MKFS_EXT4" >/dev/null 2>&1 ||
		{ echo "luckfox-vpn-overlay-post: host mkfs.ext4 must be dynamically linked for fakeroot" >&2; exit 1; }
	export RK_MKFS_EXT4
	chown 0:0 "$R/opt" "$R/var" "$R/etc" "$R/etc/init.d"
	chown -h -R 0:0 "$R/opt/vpn-web" "$R/var/www"
	chown 0:0 "$R/etc/httpd.conf" "$R/etc/init.d/S49httpd"
	exec "$@"
fi
