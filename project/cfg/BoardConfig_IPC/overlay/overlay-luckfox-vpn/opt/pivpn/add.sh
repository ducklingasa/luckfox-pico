#!/bin/bash
# pivpn add [-n name]: create a new client

. /opt/pivpn/common.sh

name=""
while [ $# -gt 0 ]; do
	case "$1" in
		-n | --name)
			name=$2
			shift 2 || die "-n needs a name"
			;;
		-h | --help)
			echo "Usage: pivpn add [-n <name>]"
			exit 0
			;;
		*) die "Unknown option: $1" ;;
	esac
done

umask 077
take_lock
require_server

if [ -z "$name" ]; then
	read -r -p "Enter a Name for the Client: " name
fi
valid_name "$name" || die "Invalid name '$name': 1-15 chars of [A-Za-z0-9._-], starting with a letter or digit"
client_exists "$name" && die "A client named '$name' already exists"
client_state "$name"
[ $? -ne 2 ] && die "A peer block for '$name' already exists in $WGCONF"

# Lowest free host address .2 - .254
declare -A used
while read -r _ _ _ ip; do
	[ -n "$ip" ] && used[${ip##*.}]=1
done <"$CLIENTS"
octet=""
for ((i = 2; i <= 254; i++)); do
	if [ -z "${used[$i]}" ]; then
		octet=$i
		break
	fi
done
[ -n "$octet" ] || die "No free IP address left in ${pivpnNET}/${subnetClass}"
client_ip=${NET_PREFIX}.${octet}

server_pub=$(cat "$WGDIR/server_pub") || die "Server public key missing"
priv=$(wg genkey) || die "wg genkey failed"
pub=$(printf '%s\n' "$priv" | wg pubkey) || die "wg pubkey failed"
psk=$(wg genpsk) || die "wg genpsk failed"

printf '%s\n' "$priv" >"$KEYDIR/${name}_priv"
printf '%s\n' "$pub" >"$KEYDIR/${name}_pub"
printf '%s\n' "$psk" >"$KEYDIR/${name}_psk"

dns=$pivpnDNS1
[ -n "$pivpnDNS2" ] && dns="$dns, $pivpnDNS2"

cat >"$CONFDIR/${name}.conf" <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${client_ip}/${subnetClass}
DNS = ${dns}
MTU = ${pivpnMTU}

[Peer]
PublicKey = ${server_pub}
PresharedKey = ${psk}
Endpoint = ${pivpnHOST}:${pivpnPORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = ${pivpnPERSISTENTKEEPALIVE}
EOF

{
	# awk 1 also terminates a last line that lacks a newline
	awk 1 "$WGCONF"
	cat <<EOF
### begin ${name} ###
[Peer]
PublicKey = ${pub}
PresharedKey = ${psk}
AllowedIPs = ${client_ip}/32
### end ${name} ###
EOF
} | replace_file "$WGCONF"

echo "${name} ${pub} $(date +%s) ${client_ip}" >>"$CLIENTS"
chmod 0600 "$KEYDIR/${name}"_* "$CONFDIR/${name}.conf" "$CLIENTS"

apply_config

echo "::: Client '${name}' added with IP ${client_ip}"
echo "::: Config: $CONFDIR/${name}.conf"
echo "::: Run 'pivpn -qr ${name}' to show it as a QR code"
