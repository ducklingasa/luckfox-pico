#!/bin/sh

if [ "$#" -ne 1 ] || [ ! -f "$1/package/Config.in" ]; then
	echo "Usage: $0 <Buildroot source directory>" >&2
	exit 1
fi

BUILDROOT_DIR=$1
SCRIPT_DIR=$(dirname "$0")
CONFIG_IN=$BUILDROOT_DIR/package/Config.in

cp -R "$SCRIPT_DIR/packages/btop" "$BUILDROOT_DIR/package/" || exit 1
cp -R "$SCRIPT_DIR/packages/vpn-web" "$BUILDROOT_DIR/package/" || exit 1

if ! grep -q 'source "package/btop/Config.in"' "$CONFIG_IN"; then
	if ! grep -q 'source "package/bubblewrap/Config.in"' "$CONFIG_IN"; then
		echo "install-custom-packages.sh: cannot find insertion point in $CONFIG_IN" >&2
		exit 1
	fi

	sed -i '/source "package\/bubblewrap\/Config.in"/a\	source "package/btop/Config.in"' "$CONFIG_IN" || exit 1
fi

if ! grep -q 'source "package/vpn-web/Config.in"' "$CONFIG_IN"; then
	sed -i '/source "package\/btop\/Config.in"/a\	source "package/vpn-web/Config.in"' "$CONFIG_IN" || exit 1
fi
