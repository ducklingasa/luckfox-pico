# Using Luckfox Pico Mini A running Buildroot as a WireGuard VPN Server

## 0. Goals & decisions

| Topic | Decision |
|---|---|
| Hardware | Luckfox Pico Mini A (RV1103, 64 MB RAM, no SPI NAND) + micro SD + added RJ45 on the internal 100 Mbit FEPHY |
| SDK integration | **New variant** (own BoardConfig, DTS, kernel fragment, Buildroot defconfig, overlay). Stock Mini config untouched |
| LAN address | DHCP + **reservation on the router** for fixed MAC `d6:af:ce:d0:c4:c3` |
| Public endpoint | `psykey.webhop.me` (No-IP DDNS, updated by the router; router has a real public IPv4) |
| WireGuard | UDP `51820`, subnet `10.6.0.0/24`, server `10.6.0.1`, IPv4 only inside the tunnel |
| Client defaults | Full tunnel, DNS `9.9.9.9, 149.112.112.112` (Quad9) |
| SSH | Keep **OpenSSH** (already in defconfig), key-only, telnet removed |
| Footprint | Camera/ISP/audio stack removed, CMA shrunk, `KERNEL_MODE_NEON` enabled for crypto |
| UI | `pivpn`-style CLI: `add, remove, list, clients, qrcode, backup, restore, on/off, help` |
| Persistence | WireGuard state on `/userdata` (separate ext4 partition), backups in `/userdata/vpn-backup` |

### SDK findings

| Topic | Finding in this SDK | Action |
|---|---|---|
| `netdev` LED trigger | `CONFIG_LEDS_TRIGGER_NETDEV` is **not set** -> `/sys/class/leds/*/device_name` won't exist | Enable in kernel fragment |
| Fixed MAC | `dwmac-rk` reads MAC from Rockchip vendor storage; only `ROCKCHIP_MTD_VENDOR_STORAGE` is built, SD boot has none -> **random MAC each boot** | `local-mac-address` in DTS + userspace fallback |
| WireGuard in kernel | Already `CONFIG_WIREGUARD=y`, but `CONFIG_WIREGUARD_DEBUG=y` (log spam incl. peer IPs) | Disable debug |
| `iproute2` | Only BusyBox `ip` is installed; `wg-quick` needs full iproute2 (`ip link add ... type wireguard`) | `BR2_PACKAGE_IPROUTE2=y` |
| `wireguard-tools` | Not selected. `wg-quick` is only built when `BR2_PACKAGE_BASH=y` (already set) | `BR2_PACKAGE_WIREGUARD_TOOLS=y` |
| `qrencode` | Not selected | `BR2_PACKAGE_LIBQRENCODE=y` + `_TOOLS=y` |
| SSH server | Defconfig already ships OpenSSH | Keep OpenSSH |
| sysctl | `S02sysctl` already loads `/etc/sysctl.d/*.conf` | Use `/etc/sysctl.d/99-wireguard.conf` |
| iptables | Legacy `iptables` with NAT/MASQUERADE/TCPMSS is in the kernel; `CONFIG_NF_TABLES` is off -> use legacy, not `iptables-nft`. `S35iptables` restores `/etc/iptables.conf` | Ship `/etc/iptables.conf` |
| eth0 config | `/etc/network/interfaces` has only `lo`; `S41dhcpcd` (dhcpcd) handles other interfaces. dhcpcd uses `duid` (can break MAC-based reservations) and would also touch `wg0` | Overlay `/etc/dhcpcd.conf` |
| Secrets | A `wg0.conf` in the rootfs overlay would put the **server private key into git**. Overlay rsync also forces `go=rX` (every overlay file ends up world-readable, including the stock `/etc/shadow`) | Generate keys on first boot on `/userdata`; never ship secrets in the overlay |
| Camera app | `S21appinit` -> `RkLunch.sh` starts `rkipc`; 24 MB CMA reserved | Remove via post-build script, disable ISP/CSI in DTS, shrink CMA |
| Insecure defaults | `S50telnet` enabled, root password `luckfox`, `S99_auto_reboot` test hook | Remove/override |
| Init order | An `S50` script would race `S50sshd`; WireGuard must start after `S41dhcpcd` | Use `S48wireguard` |

---

## 1. Hardware

* RJ45 jack **with integrated magnetics** (e.g. HR911105A) wired to the RV1103 FEPHY TX+/TX-/RX+/RX- pads.
* Activity LED -> header pin 11 = `GPIO1_C5` (mux shared with **UART4_M1**).
* Link LED -> header pin 12 = `GPIO1_D0` (mux shared with **UART3_M1**).
  Consequence: UART3/UART4 must stay disabled and must not be enabled with `luckfox-config`.
* Use a current-limiting resistor per LED (3.3 V GPIO).

## 2. SDK integration (new variant)

| Purpose | File |
|---|---|
| Board config | `project/cfg/BoardConfig_IPC/BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk` |
| Device tree | `sysdrv/source/kernel/arch/arm/boot/dts/rv1103g-luckfox-pico-mini-vpn.dts` |
| Kernel fragment | `sysdrv/source/kernel/arch/arm/configs/luckfox_rv1106-vpn.config` |
| Buildroot defconfig | `sysdrv/tools/board/buildroot/luckfox_pico_vpn_defconfig` |
| Copy defconfig into Buildroot | `sysdrv/Makefile`: add a `cp .../luckfox_pico_vpn_defconfig` line next to the two existing `luckfox_pico*_defconfig` copies (both the extract and the re-extract paths) |
| Post-build script | `project/cfg/BoardConfig_IPC/luckfox-vpn-post.sh` (must be `chmod +x`, it is executed directly) |
| Overlay | `project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/` |

### 2.1 BoardConfig (copy of the Mini SD config, changes only)

```sh
export LF_ORIGIN_BOARD_CONFIG=BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk
export RK_KERNEL_DTS=rv1103g-luckfox-pico-mini-vpn.dts
export RK_KERNEL_DEFCONFIG_FRAGMENT=luckfox_rv1106-vpn.config
export RK_BUILDROOT_DEFCONFIG=luckfox_pico_vpn_defconfig
export RK_BOOTARGS_CMA_SIZE="1M"          # was 24M; verify boot, fall back to 4M if a driver complains
export RK_POST_BUILD_SCRIPT=luckfox-vpn-post.sh
export RK_POST_OVERLAY="overlay-luckfox-config overlay-luckfox-buildroot-init overlay-luckfox-buildroot-shadow overlay-luckfox-vpn"
# remove: RK_APP_TYPE, RK_CAMERA_SENSOR_IQFILES, RK_CAMERA_SENSOR_CAC_BIN, RK_ENABLE_ROCKCHIP_TEST
```

`overlay-luckfox-vpn` is last, so it overrides `sshd_config` from `overlay-luckfox-buildroot-shadow`.
If the build breaks without `RK_APP_TYPE`, keep it and rely on the post-build script removing `S21appinit`.

### 2.2 Selecting the variant

`./build.sh lunch` builds names from fixed lists and won't offer the new file. Select it manually:

```sh
cd ~/luckfox-pico
ln -rfs project/cfg/BoardConfig_IPC/BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk .BoardConfig.mk
./build.sh clean      # first time only: Buildroot/kernel configs change
./build.sh
```

## 3. Kernel

### 3.1 Device tree `rv1103g-luckfox-pico-mini-vpn.dts`

```dts
// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
#include "rv1103g-luckfox-pico-mini.dts"

/ {
	model = "Luckfox Pico Mini VPN";
};

/**********ETH**********/
&gmac {
	status = "okay";
	local-mac-address = [d6 af ce d0 c4 c3];   /* locally administered, unicast */
};

/* leds node already exists (compatible + work_led) in rv1103-luckfox-pico-ipc.dtsi */
&leds {
	/* PIN 11 GPIO1_C5_d (UART4_M1 mux) */
	eth_act {
		gpios = <&gpio1 RK_PC5 GPIO_ACTIVE_HIGH>;
		linux,default-trigger = "netdev";
		default-state = "off";
	};
	/* PIN 12 GPIO1_D0_d (UART3_M1 mux) */
	eth_link {
		gpios = <&gpio1 RK_PD0 GPIO_ACTIVE_HIGH>;
		linux,default-trigger = "netdev";
		default-state = "off";
	};
};

/* pins reused for LEDs */
&uart3 { status = "disabled"; };
&uart4 { status = "disabled"; };

/* camera / ISP / audio not needed on a VPN server */
&csi2_dphy_hw { status = "disabled"; };
&csi2_dphy0 { status = "disabled"; };
&mipi0_csi2 { status = "disabled"; };
&rkcif { status = "disabled"; };
&rkcif_mipi_lvds { status = "disabled"; };
&rkcif_mipi_lvds_sditf { status = "disabled"; };
&rkisp { status = "disabled"; };
&rkisp_vir0 { status = "disabled"; };
&i2c4 { status = "disabled"; };
&i2s0_8ch { status = "disabled"; };
&acodec { status = "disabled"; };
```

Notes:
* U-Boot may still inject an `ethaddr` into the DT. Section 5.1 sets the MAC again from userspace as a fallback.
* The netdev trigger cannot be bound to `eth0` from the DT on 5.10, so section 5.1 does it at boot.

### 3.2 Kernel fragment `luckfox_rv1106-vpn.config`

```
CONFIG_LEDS_TRIGGER_NETDEV=y
# CONFIG_WIREGUARD_DEBUG is not set
CONFIG_KERNEL_MODE_NEON=y
CONFIG_CRYPTO_CHACHA20_NEON=y
CONFIG_CRYPTO_POLY1305_ARM=y
CONFIG_CRYPTO_CURVE25519_NEON=y
CONFIG_CRYPTO_BLAKE2S_ARM=y
```

Verify on target with `zcat /proc/config.gz` (if enabled) or `objs_kernel/.config` after the build.

## 4. Root filesystem

### 4.1 Buildroot `luckfox_pico_vpn_defconfig` = `luckfox_pico_defconfig` +

```
BR2_TARGET_GENERIC_HOSTNAME="luckfox-vpn"
BR2_PACKAGE_WIREGUARD_TOOLS=y
BR2_PACKAGE_IPROUTE2=y
BR2_PACKAGE_LIBQRENCODE=y
BR2_PACKAGE_LIBQRENCODE_TOOLS=y
```

Already present and reused: `bash`, `openssh`, `iptables` (legacy), `ntp` (ntpd), `iperf3`, `curl`. BusyBox provides `flock`, `tar`, `date`, `mktemp`.
Optional slimming: drop Python, Samba and other unused packages from this defconfig to save RAM and space.

### 4.2 Post-build script `luckfox-vpn-post.sh`

Runs after rootfs assembly and **before** the overlays are copied. It removes stock init scripts the server does not need:

```bash
#!/bin/bash
R=$RK_PROJECT_PACKAGE_ROOTFS_DIR/etc/init.d
rm -f $R/S21appinit $R/S50telnet $R/S99_auto_reboot $R/S60micinit $R/S99hciinit
```

Keep `S20linkmount` (mounts `/userdata`), `S50usbdevice` and `S99usb0config`. USB-RNDIS at `172.32.0.93` stays available as a rescue path.

### 4.3 Overlay tree `overlay-luckfox-vpn/`

```
etc/
├── dhcpcd.conf                      # clientid instead of duid, denyinterfaces wg* usb0
├── iptables.conf                    # firewall + NAT (restored by S35iptables)
├── sysctl.d/99-wireguard.conf       # net.ipv4.ip_forward=1
├── ssh/sshd_config                  # key-only
├── pivpn/wireguard/setupVars.conf   # non-secret settings (port, subnet, DNS, endpoint...)
└── init.d/
    ├── S38harden                    # chmod 0600 /etc/shadow (overlay rsync makes it 0644)
    ├── S39lan                       # fixed MAC fallback + netdev LEDs (before S41dhcpcd)
    └── S48wireguard                 # first-boot keygen + wg-quick up/down
root/.ssh/authorized_keys            # PUBLIC key(s) only
usr/sbin/pivpn                       # CLI dispatcher
opt/pivpn/*.sh                       # sub-commands
```

**Never** put private keys, PSKs or password hashes you care about in the overlay. They would end up in git and world-readable.

## 5. Networking

### 5.1 `/etc/init.d/S39lan`

```sh
#!/bin/sh
MAC=d6:af:ce:d0:c4:c3

case $1 in
	start)
		if [ "$(cat /sys/class/net/eth0/address)" != "$MAC" ]; then
			ip link set eth0 down
			ip link set eth0 address $MAC
		fi
		ip link set eth0 up

		echo eth0 > /sys/class/leds/eth_link/device_name
		echo 1 > /sys/class/leds/eth_link/link

		echo eth0 > /sys/class/leds/eth_act/device_name
		echo 1 > /sys/class/leds/eth_act/rx
		echo 1 > /sys/class/leds/eth_act/tx
		;;
	stop)
		;;
	*)
		echo "Usage: $0 {start|stop}"
		exit 1
		;;
esac
```

### 5.2 `/etc/dhcpcd.conf` (stock + changes)

```
clientid                # send MAC as client-id -> router reservation by MAC is reliable
#duid                   # (disabled)
denyinterfaces wg* usb0 # dhcpcd must not touch the tunnel or the rescue interface
persistent
option domain_name_servers, domain_name, domain_search, host_name
option classless_static_routes, interface_mtu
require dhcp_server_identifier
```

### 5.3 `/etc/sysctl.d/99-wireguard.conf`

```
net.ipv4.ip_forward = 1
```

### 5.4 `/etc/iptables.conf`

```
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i usb0 -j ACCEPT
-A INPUT -i eth0 -p udp --dport 51820 -j ACCEPT
-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT
-A INPUT -i wg0  -p tcp --dport 22 -j ACCEPT
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i wg0 -o eth0 -j ACCEPT
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.6.0.0/24 -o eth0 -j MASQUERADE
COMMIT
```

* SSH on `eth0` is only reachable from the LAN because the router forwards only UDP 51820.
* Client-to-client traffic (`wg0 -> wg0`) is blocked by default. Add `-A FORWARD -i wg0 -o wg0 -j ACCEPT` if needed.
* `S35iptables stop` runs `iptables-save -f /etc/iptables.conf`, so runtime changes get persisted on shutdown.

## 6. WireGuard server

### 6.1 Storage layout (persistent on `/userdata`)

```
/etc/wireguard -> /userdata/wireguard        (symlink created by S48wireguard)
/userdata/wireguard/            0700
├── wg0.conf                    0600
├── server_priv / server_pub    0600
├── keys/<name>_priv|_pub|_psk  0600
└── configs/
    ├── clients.txt             "<name> <pubkey> <epoch> <ip>"
    └── <name>.conf             0600
/userdata/vpn-backup/           0700  pivpnbackup-YYYYmmdd-HHMMSS.tgz
```

### 6.2 `/etc/pivpn/wireguard/setupVars.conf`

```sh
IPv4dev=eth0
pivpnDEV=wg0
pivpnPORT=51820
pivpnHOST=psykey.webhop.me
pivpnNET=10.6.0.0
subnetClass=24
pivpnDNS1=9.9.9.9
pivpnDNS2=149.112.112.112
ALLOWED_IPS="0.0.0.0/0, ::/0"   # ::/0 blackholes client IPv6 -> no IPv6 leak (IPv6-only sites won't work)
pivpnMTU=1420
pivpnPERSISTENTKEEPALIVE=25
BACKUP_DIR=/userdata/vpn-backup
```

### 6.3 `/etc/init.d/S48wireguard`

* `start`:
  1. Wait until `/userdata` is mounted (done by `S20linkmount`).
  2. Create `/userdata/wireguard` with `umask 077` and the `/etc/wireguard` symlink.
  3. On first boot only, create `server_priv` (`wg genkey`) and `server_pub`, then render `wg0.conf` from `setupVars.conf`.
  4. Run `wg-quick up wg0`.
* `stop`: `wg-quick down wg0`.
* Runs after `S41dhcpcd`. `wg0` listens on all addresses, so it doesn't need eth0's lease yet.

Server `wg0.conf` template (no PostUp/PostDown; the firewall lives in `/etc/iptables.conf`):

```ini
[Interface]
Address = 10.6.0.1/24
ListenPort = 51820
MTU = 1420
PrivateKey = <server_priv>

### begin phone ###
[Peer]
PublicKey = <phone_pub>
PresharedKey = <phone_psk>
AllowedIPs = 10.6.0.2/32
### end phone ###
```

Client template `configs/<name>.conf`:

```ini
[Interface]
PrivateKey = <client_priv>
Address = 10.6.0.N/24
DNS = 9.9.9.9, 149.112.112.112
MTU = 1420

[Peer]
PublicKey = <server_pub>
PresharedKey = <client_psk>
Endpoint = psykey.webhop.me:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

## 7. User interface: `pivpn` CLI

* Bash script at `/usr/sbin/pivpn` dispatching to `/opt/pivpn/*.sh`.
* Every changing command takes `flock /run/pivpn.lock` and runs `umask 077`.
* Changes are applied live with `wg syncconf wg0 <(wg-quick strip wg0)`. `/dev/fd` is provided by inittab.
* Written from scratch in the PiVPN style. If PiVPN code is copied, keep its MIT license notice.

| Command | Alias | Behaviour |
|---|---|---|
| `pivpn add [-n name]` | `-a` | Validate name (`[A-Za-z0-9._-]`, max 15 chars, unique). Pick lowest free IP `.2-.254`, generate priv/pub/psk, append a `### begin/end name ###` peer block, write `configs/name.conf`, append to `clients.txt`, syncconf |
| `pivpn remove name [-y]` | `-r` | Confirm, delete the peer block (sed range on markers), keys, conf and `clients.txt` line, syncconf |
| `pivpn list` | `-l` | Table of name / public key / creation date / IP / `[disabled]` flag from `clients.txt` |
| `pivpn clients` | `-c` | `wg show wg0 dump` joined with `clients.txt`: name, remote endpoint, virtual IP, RX/TX (human readable), last handshake (`date -d @epoch`) |
| `pivpn qrcode name` | `-qr` | `qrencode -t ansiutf8 < configs/name.conf` |
| `pivpn off name` / `pivpn on name` | `-off` / `-on` | Comment out or restore the peer block with a `#[disabled] ` prefix, syncconf |
| `pivpn backup` | `-bk` | `tar czf $BACKUP_DIR/pivpnbackup-$(date +%Y%m%d-%H%M%S).tgz` of `/userdata/wireguard` + `/etc/pivpn`, chmod 600, keep the last 5, print an `scp` hint |
| `pivpn restore file.tgz` | `-rs` | Validate the archive, confirm, `wg-quick down`, extract, fix permissions, `wg-quick up` |
| `pivpn help` | `-h` | Usage |

Time note: the Mini has no RTC. Creation dates and handshake times are only correct after ntpd (`S49ntp`) has synced. WireGuard itself works regardless.

## 8. Hardening

* Telnet is removed (post-build script).
* `sshd_config`: `PermitRootLogin prohibit-password`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`.
  **Test key login first**. Serial console and USB `172.32.0.93` remain as rescue paths.
* Change the root password on first login with `passwd`. Do not put a plaintext password in the defconfig.
* `S38harden` runs `chmod 0600 /etc/shadow` at boot.
* `WIREGUARD_DEBUG` is disabled.
* Firewall has a default-drop INPUT/FORWARD policy (section 5.4).

## 9. Router configuration

1. DHCP reservation: MAC `d6:af:ce:d0:c4:c3` -> fixed LAN IP.
2. Port forward: UDP 51820 (WAN) -> reserved IP:51820. Nothing else.
3. No-IP DDNS for `psykey.webhop.me` on the router. Free No-IP hostnames must be confirmed every 30 days.
4. Test from **mobile data**, not Wi-Fi. Many routers lack NAT loopback.

## 10. Build, flash, update

* First flash: `output/image/sd_update.img`. This also **overwrites `/userdata`**, so run `pivpn backup` and `scp` the archive off the device before every full reflash.
* Later updates: write only `boot.img` / `rootfs.img` to their partitions. Layout: `env, idblock, uboot, boot, userdata, rootfs`; check partition numbers with `lsblk` first. This keeps `/userdata`.

## 11. Verification checklist

| # | Check | Expected |
|---|---|---|
| 1 | `cat /sys/class/net/eth0/address` after 2 reboots | `d6:af:ce:d0:c4:c3` both times |
| 2 | `cat /sys/class/net/eth0/speed`, `dmesg \| grep -i eth` | 100, link up |
| 3 | Unplug/replug cable, generate traffic | Link LED follows the cable, act LED blinks |
| 4 | `ip -4 addr show eth0` | Reserved IP |
| 5 | `free -m` before and after camera stripping | Noticeably more free RAM; record numbers |
| 6 | `sysctl net.ipv4.ip_forward`, `iptables -S`, `iptables -t nat -S` | 1, rules from 5.4 |
| 7 | `wg show` | `wg0` listening on 51820 |
| 8 | `pivpn add -n phone && pivpn -qr phone` | QR scans in the WireGuard app |
| 9 | Phone on mobile data: connect, open `ifconfig.me` | Home public IP; `pivpn -c` shows handshake + traffic |
| 10 | DNS leak test / IPv6 test on phone | Only Quad9; no IPv6 leak |
| 11 | `pivpn -off phone`, then `-on` | Tunnel stops, then works again without restart |
| 12 | `iperf3` LAN <-> client through tunnel, with and without `KERNEL_MODE_NEON` | Record throughput; NEON should not be slower |
| 13 | `pivpn -bk`, reflash rootfs only, `pivpn -rs` | Clients keep working without re-import |
| 14 | `ssh` with password | Rejected; key works |
| 15 | Port scan from WAN | Only UDP 51820 open (WireGuard won't answer unauthenticated packets) |

## 12. Open risks

* If the `local-mac-address` override doesn't win against U-Boot, the S39 fallback handles it. The fallback must then stay.
* Removing `RK_APP_TYPE` and shrinking CMA is not done by any stock Luckfox config. Check the build and boot log for media-driver errors.
* `wg-quick` dependencies (`bash`, `iproute2`) on uClibc: confirm `wg-quick up` works before writing the `pivpn` scripts.
* The SD card is the single point of failure. Keep off-device backups and consider a good-quality endurance card.
