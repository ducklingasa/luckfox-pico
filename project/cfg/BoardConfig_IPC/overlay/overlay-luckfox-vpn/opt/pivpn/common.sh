#!/bin/bash
# Shared helpers for the pivpn sub-commands (sourced, not executed).

SETUPVARS=${PIVPN_SETUPVARS:-/etc/pivpn/wireguard/setupVars.conf}
WGDIR=${PIVPN_WGDIR:-/etc/wireguard}
LOCKFILE=${PIVPN_LOCKFILE:-/run/pivpn.lock}

if [ ! -r "$SETUPVARS" ]; then
	echo "::: $SETUPVARS not found" >&2
	exit 1
fi
# shellcheck source=/dev/null
. "$SETUPVARS"

pivpnDEV=${pivpnDEV:-wg0}
WGCONF=$WGDIR/$pivpnDEV.conf
KEYDIR=$WGDIR/keys
CONFDIR=$WGDIR/configs
CLIENTS=$CONFDIR/clients.txt
NET_PREFIX=${pivpnNET%.*}
DISABLED_PREFIX='#[disabled] '

err() { echo "::: $*" >&2; }
die() {
	err "$@"
	exit 1
}

# Serialise all changing commands
take_lock() {
	exec 9>"$LOCKFILE" || die "Cannot open $LOCKFILE"
	flock -n 9 || die "Another pivpn command is running"
}

require_server() {
	[ -f "$WGCONF" ] || die "$WGCONF not found. Is /userdata mounted and S48wireguard started?"
	mkdir -p "$KEYDIR" "$CONFDIR"
	[ -f "$CLIENTS" ] || : >"$CLIENTS"
}

valid_name() {
	[[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$ ]]
}

client_exists() {
	awk -v n="$1" '$1 == n { found = 1 } END { exit !found }' "$CLIENTS"
}

client_names() {
	awk 'NF { print $1 }' "$CLIENTS"
}

# 0 = enabled, 1 = disabled, 2 = no peer block
client_state() {
	if grep -qxF "${DISABLED_PREFIX}### begin $1 ###" "$WGCONF"; then
		return 1
	elif grep -qxF "### begin $1 ###" "$WGCONF"; then
		return 0
	fi
	return 2
}

# Replace a file with stdin, keeping it 0600
replace_file() {
	local tmp
	tmp=$(mktemp "$1.XXXXXX") || die "mktemp failed"
	cat >"$tmp" || {
		rm -f "$tmp"
		die "Writing $1 failed"
	}
	chmod 0600 "$tmp"
	mv -f "$tmp" "$1"
}

wg_running() {
	wg show "$pivpnDEV" >/dev/null 2>&1
}

# Apply wg0.conf to the running interface without dropping other peers
apply_config() {
	if wg_running; then
		wg syncconf "$pivpnDEV" <(wg-quick strip "$pivpnDEV") || die "wg syncconf failed"
	else
		err "$pivpnDEV is not running; changes take effect on the next start (/etc/init.d/S48wireguard start)"
	fi
}

confirm() {
	local answer
	read -r -p "$1 [y/N] " answer
	[[ $answer =~ ^[Yy]$ ]]
}

# Ask for a client name when none was given on the command line
prompt_client() {
	local name
	if [ ! -s "$CLIENTS" ]; then
		die "There are no clients"
	fi
	echo "::  Clients  ::" >&2
	client_names | awk '{ printf "%3d) %s\n", NR, $0 }' >&2
	read -r -p "Client name: " name
	echo "$name"
}

human_bytes() {
	awk -v b="$1" 'BEGIN {
		split("B KiB MiB GiB TiB", u, " ")
		i = 1
		while (b >= 1024 && i < 5) { b /= 1024; i++ }
		if (i == 1) printf "%d %s", b, u[i]; else printf "%.1f %s", b, u[i]
	}'
}

fmt_date() {
	date -d "@$1" '+%d %b %Y, %H:%M' 2>/dev/null || echo "$1"
}
