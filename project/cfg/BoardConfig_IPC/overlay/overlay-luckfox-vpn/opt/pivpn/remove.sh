#!/bin/bash
# pivpn remove [name...] [-y]: delete clients

. /opt/pivpn/common.sh

names=()
yes=0
while [ $# -gt 0 ]; do
	case "$1" in
		-y | --yes) yes=1 ;;
		-h | --help)
			echo "Usage: pivpn remove [<name>...] [-y]"
			exit 0
			;;
		-*) die "Unknown option: $1" ;;
		*) names+=("$1") ;;
	esac
	shift
done

umask 077
take_lock
require_server

if [ ${#names[@]} -eq 0 ]; then
	names=("$(prompt_client)")
fi

for name in "${names[@]}"; do
	valid_name "$name" || die "Invalid name '$name'"
	client_exists "$name" || die "Client '$name' does not exist"
done

for name in "${names[@]}"; do
	if [ $yes -eq 0 ] && ! confirm "Do you really want to delete '$name'?"; then
		echo "::: Skipping '$name'"
		continue
	fi

	# Drop the peer block, enabled or disabled
	awk -v n="$name" -v p="$DISABLED_PREFIX" '
		{ line = $0; if (index(line, p) == 1) line = substr(line, length(p) + 1) }
		line == "### begin " n " ###" { skip = 1 }
		!skip { print }
		line == "### end " n " ###" { skip = 0 }
	' "$WGCONF" | replace_file "$WGCONF"

	awk -v n="$name" '$1 != n' "$CLIENTS" | replace_file "$CLIENTS"
	rm -f "$KEYDIR/${name}_priv" "$KEYDIR/${name}_pub" "$KEYDIR/${name}_psk" "$CONFDIR/${name}.conf"

	echo "::: Client '$name' removed"
done

apply_config
