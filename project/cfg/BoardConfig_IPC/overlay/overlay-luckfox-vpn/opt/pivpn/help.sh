#!/bin/bash
# pivpn help

cat <<'EOF'
::: Control all PiVPN-style WireGuard functions on the Luckfox VPN server
:::
::: Usage: pivpn <command> [option]
:::
::: Commands:
:::  -a,   add              Create a client conf profile (-n <name>)
:::  -c,   clients          List any connected clients to the server
:::  -l,   list             List all clients
:::  -qr,  qrcode           Show the QR code of a client for use with the mobile app
:::  -r,   remove           Remove a client (<name>... [-y])
:::  -off, off              Disable a client (<name>... [-y])
:::  -on,  on               Enable a client (<name>...)
:::  -bk,  backup           Backup VPN configs and keys to /userdata/vpn-backup
:::  -rs,  restore          Restore a backup (<file.tgz> [-y])
:::  -h,   help             Show this help dialog
EOF
