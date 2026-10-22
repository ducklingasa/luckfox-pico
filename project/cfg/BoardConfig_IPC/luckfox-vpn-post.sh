#!/bin/bash
# Runs after rootfs assembly and before the overlays are copied.
# Removes stock init scripts the VPN server does not need.
# S60micinit / S99hciinit are re-added later by overlay-luckfox-buildroot-init,
# so overlay-luckfox-vpn overrides them with no-op scripts instead.

R=$RK_PROJECT_PACKAGE_ROOTFS_DIR/etc/init.d

if [ -z "$RK_PROJECT_PACKAGE_ROOTFS_DIR" ] || [ ! -d "$R" ]; then
	echo "luckfox-vpn-post.sh: rootfs dir not found ($R)" >&2
	exit 1
fi

for f in S21appinit S50telnet S99_auto_reboot; do
	if [ -e "$R/$f" ]; then
		echo "luckfox-vpn-post.sh: removing $R/$f"
		rm -f "$R/$f"
	fi
done

exit 0
