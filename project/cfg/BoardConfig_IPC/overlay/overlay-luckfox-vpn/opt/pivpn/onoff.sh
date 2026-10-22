#!/bin/bash
# pivpn off|on [name...] [-y]: disable or re-enable clients without deleting them

. /opt/pivpn/common.sh

mode=$1
shift
case "$mode" in
	on | off) ;;
	*) die "Usage: pivpn {on|off} [<name>...] [-y]" ;;
esac

names=()
yes=0
while [ $# -gt 0 ]; do
	case "$1" in
		-y | --yes) yes=1 ;;
		-h | --help)
			echo "Usage: pivpn $mode [<name>...] [-y]"
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

changed=0
for name in "${names[@]}"; do
	valid_name "$name" || die "Invalid name '$name'"
	client_state "$name"
	state=$?
	if [ $state -eq 2 ]; then
		err "Client '$name' has no peer block in $WGCONF"
		continue
	fi
	if [ "$mode" = off ] && [ $state -eq 1 ]; then
		echo "::: Client '$name' is already disabled"
		continue
	fi
	if [ "$mode" = on ] && [ $state -eq 0 ]; then
		echo "::: Client '$name' is already enabled"
		continue
	fi
	if [ "$mode" = off ] && [ $yes -eq 0 ] && ! confirm "Disable client '$name'?"; then
		continue
	fi

	awk -v n="$name" -v p="$DISABLED_PREFIX" -v mode="$mode" '
		{ line = $0; if (index(line, p) == 1) line = substr(line, length(p) + 1) }
		line == "### begin " n " ###" { inblock = 1 }
		inblock { print (mode == "off" ? p line : line) }
		!inblock { print }
		line == "### end " n " ###" { inblock = 0 }
	' "$WGCONF" | replace_file "$WGCONF"

	changed=1
	if [ "$mode" = off ]; then
		echo "::: Client '$name' disabled"
	else
		echo "::: Client '$name' enabled"
	fi
done

[ $changed -eq 1 ] && apply_config
exit 0
