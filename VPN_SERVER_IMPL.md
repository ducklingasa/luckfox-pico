# Luckfox Pico Mini A WireGuard VPN server: implementation and operation

This guide records the implementation, hardware findings, and operating procedures
discussed during bring-up. See [VPN_SERVER_PLAN.md](./VPN_SERVER_PLAN.md) for the
original design, hardware connections, and detailed configuration templates.

## 1. Current configuration and confirmed results

| Setting | Value |
|---|---|
| Board | Luckfox Pico Mini A, RV1103, 64 MB RAM, microSD boot |
| LAN interface | `eth0`, DHCP with a router reservation |
| Reserved LAN address | **192.168.0.10** (intentionally changed from the earlier 192.168.0.52) |
| Fixed LAN MAC | `d6:af:ce:d0:c4:c3` |
| SSH account | `root` |
| SSH authentication on LAN/tunnel | Public key only |
| USB rescue address | `172.32.0.93`, with a password-login exception for SSH |
| Public endpoint | `psykey.webhop.me:51820`, UDP |
| Tunnel interface/server address | `wg0`, `10.6.0.1/24` |
| Client address pool | `10.6.0.2` through `10.6.0.254` |
| Client DNS | Quad9: `9.9.9.9`, `149.112.112.112` |
| Client default routes | `0.0.0.0/0, ::/0`; tunnel service is IPv4-only |
| Rootfs partition | Fixed `6G(rootfs)`, meaning 6 GiB |
| Persistent VPN data | `/userdata/wireguard` |
| Backups | `/userdata/vpn-backup`, newest five retained |

Confirmed during bring-up:

- The user built the firmware successfully.
- The original grow-to-end rootfs layout did not boot successfully on the tested
  card. After limiting rootfs to 6 GiB, the board started working. This is an
  observed workaround for this setup, not proof of a universal ext4 size limit.
- Ethernet negotiated 100 Mbps/full duplex and obtained a DHCP lease.
- ADB became available, and SSH became usable after correcting ownership of the
  root SSH directories/key file.
- The key fingerprint on the board matched the intended public key.
- Backup creation and a PSCP download succeeded. SHA-256 hashes on the board and
  PC matched.

Do not infer that every test below has passed from those results. In particular,
check mobile-data routing, DNS/IPv6 behavior, peer revocation, reboot persistence,
and restore on the actual hardware.

Earlier development checks:

- Kernel fragment merged and the VPN DTB compiled in scratch output directories.
- Buildroot defconfig round-tripped with its selected options retained.
- Init scripts and CLI commands passed 56 checks using the target ARM rootfs
  under QEMU. `wg`, `wg-quick`, and `qrencode` were stand-ins in those checks;
  this did not validate real tunnel operation.
- The SSH ownership correction was subsequently tested on isolated temporary
  files, including repeated start and a missing authorized-keys file.
- All six SD-card configs passed the SDK partition parser with a 6 GiB rootfs.

## 2. Implementation files and design differences

| Purpose | File |
|---|---|
| VPN board selection | [BoardConfig](./project/cfg/BoardConfig_IPC/BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk) |
| Ethernet, LEDs, disabled camera/audio | [Device tree](./sysdrv/source/kernel/arch/arm/boot/dts/rv1103g-luckfox-pico-mini-vpn.dts) |
| Netdev LED trigger and NEON crypto | [Kernel fragment](./sysdrv/source/kernel/arch/arm/configs/luckfox_rv1106-vpn.config) |
| Userspace package selection | [Buildroot defconfig](./sysdrv/tools/board/buildroot/luckfox_pico_vpn_defconfig) |
| `stat` support for wg-quick | [BusyBox fragment](./sysdrv/tools/board/buildroot/busybox-vpn.fragment) |
| Copying the VPN defconfig into Buildroot | [sysdrv/Makefile](./sysdrv/Makefile) |
| Removing stock services | [Post-build script](./project/cfg/BoardConfig_IPC/luckfox-vpn-post.sh) |
| Runtime configuration and tools | [VPN overlay](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/) |

Important implementation details:

1. The post-build script runs before overlays. Audio/Bluetooth init scripts are
   added by an earlier overlay, so the VPN overlay replaces them with no-op
   scripts instead of relying on deletion in the post-build script.
2. BusyBox needs `stat` with formatted output because `wg-quick` checks config
   permissions using `stat -c`. The VPN-specific fragment enables it.
3. BusyBox tar lacks gzip integration here. Backups and restores pipe between
   `tar` and `gzip` explicitly.
4. The overlay copy preserves build-host ownership and makes files readable by
   other users. [S38harden](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/etc/init.d/S38harden)
   corrects root SSH ownership/permissions and tightens password-file permissions.
5. LAN/tunnel SSH is key-only; USB SSH retains a password rescue exception.
6. `S35iptables stop` flushes filter rules; it does not save runtime changes.
   Use `/etc/init.d/S35iptables save` explicitly to persist them.
7. `remove`, `on`, and `off` accept multiple client names. Names must start with
   a letter or digit and contain at most 15 characters from `[A-Za-z0-9._-]`.
8. Restore keeps the previous WireGuard data directory at
   `/userdata/wireguard.prev`. A subsequent restore replaces that previous copy.

## 3. Required SSH public-key format

### 3.1 OpenSSH authorized_keys format

Put public keys in the overlay's
[authorized_keys](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/root/.ssh/authorized_keys).
Each key must occupy **one physical line**:

```text
ssh-rsa <complete-base64-public-key> ducklingasa-adam-kollar
```

The angle-bracket text above is a placeholder, not a usable key. Do not truncate
the actual Base64 value or insert line breaks. Multiple keys use separate lines.
Use Unix LF line endings for overlay files, especially executable scripts.

The comment `ducklingasa-adam-kollar` is a label, **not a username**. Login is as
`root`, because the key is installed under `/root/.ssh`.

Never place a private key, a PuTTY `.ppk` file, or a private-key passphrase in the
overlay, repository, documentation, or board's authorized-keys file.

### 3.2 Convert an SSH2/RFC 4716 public key

This multi-line format cannot be pasted directly into OpenSSH authorized_keys:

```text
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "ducklingasa-adam-kollar"
<wrapped-public-key-data>
---- END SSH2 PUBLIC KEY ----
```

Save the complete public-key block as `public-key.ssh2`. In Linux/WSL, convert it:

```sh
ssh-keygen -i -m RFC4716 -f public-key.ssh2 > public-key.openssh
ssh-keygen -lf public-key.openssh
```

Copy the converted one-line key into the overlay file; append the label if the
conversion did not preserve it. Alternatively, PuTTYgen displays a field named
**Public key for pasting into OpenSSH authorized_keys file**. Copy that entire
field rather than the multi-line SSH2 export.

The configured RSA key is 4096 bits, with fingerprint:

```text
SHA256:ulxHABE1lz7KurC4I+bi+eBXPEfphE0WJIU5NIzbtxE
```

The `ssh-rsa` key type does not require the obsolete RSA/SHA-1 signature scheme.
Modern PuTTY/OpenSSH can authenticate this RSA key with RSA/SHA-2 signatures.
Do not enable obsolete SHA-1 authentication just to bypass a client problem.

### 3.3 Required ownership and permissions

On the running board:

```sh
ls -ld /root /root/.ssh
ls -l /root/.ssh/authorized_keys
ssh-keygen -lf /root/.ssh/authorized_keys
```

Expected:

| Path | Owner/group | Permissions |
|---|---|---|
| `/root` | `root:root` | `0700`, `drwx------` |
| `/root/.ssh` | `root:root` | `0700`, `drwx------` |
| `/root/.ssh/authorized_keys` | `root:root` | `0600`, `-rw-------` |

The first image retained UID/GID `1000:1000` from the build host. Despite correct
mode bits, OpenSSH refused authentication with:

```text
Authentication refused: bad ownership or modes for file /root/.ssh/authorized_keys
```

Fix an already-flashed board through ADB or another working console:

```sh
chown root:root /root /root/.ssh /root/.ssh/authorized_keys
chmod 0700 /root /root/.ssh
chmod 0600 /root/.ssh/authorized_keys
```

No SSH restart is needed; retry login. The corrected source hardening script
applies this ownership fix at boot in future firmware builds. A manual change on
the current card does not automatically update older firmware images.

### 3.4 Connect from a PC

PuTTY settings:

- Host: `192.168.0.10`, port `22`, connection type SSH.
- Auto-login username: `root`.
- Under **Connection -> SSH -> Auth -> Credentials**, select the matching
  private `.ppk` file. Enter its passphrase when prompted.
- Use PuTTYgen to compare the public-key fingerprint if unsure which file matches.
- PuTTY's Event Log can reveal whether Pageant supplied a different key.

With an OpenSSH-format private key:

```sh
ssh -i /path/to/private_key root@192.168.0.10
```

Once the VPN works, `root@10.6.0.1` is also reachable through the tunnel.
Keep private keys on the PC; they do not belong on the server for inbound login.

## 4. Fixed 6 GiB rootfs partition

All six SD-card BoardConfigs now end their partition layout with `6G(rootfs)`
instead of `-(rootfs)`. eMMC/NAND configs were not changed by this update.

For the Mini VPN variant:

```text
32K(env),512K@32K(idblock),256K(uboot),32M(boot),256M(userdata),6G(rootfs)
```

The SDK interprets `G` as a binary unit:

- Rootfs partition size: **6,442,450,944 bytes = 6 GiB = 6,144 MiB**.
- Rootfs starts at byte **302,809,088**, or sector **591,424** with 512-byte sectors.
- Rootfs ends at byte **6,745,260,032** (exclusive).
- Use an **8 GB or larger** card. Space beyond the configured partitions is not
  assigned to rootfs.
- These offsets describe the Mini VPN layout. The stock Pico variant has a
  different U-Boot size; do not blindly reuse Mini offsets on another board.

Distinguish partition size from image-file size, filesystem size, and used space.
The earlier grow-to-end build's rootfs image was about 198.27 MiB, not the size of
the whole card. Fixed-size image generation may produce larger image files.
On the board, `df -h /` reports the mounted filesystem, with filesystem overhead;
it will not report exactly 6.00 GiB of usable space.

The stock mount script attempts to resize the filesystem to its partition. With
the fixed layout this must remain within the configured 6 GiB partition, rather
than consuming the entire card.

**Changing only the source config does not modify an existing card or old images.**
Regenerate firmware and recreate the card to apply the changed layout. A full
reflash overwrites userdata too; copy a VPN backup off-device first.

## 5. Build and SD-card creation

### 5.1 Build selection

Build on the development machine, not on the board. For this WSL environment:

```sh
export PATH=/home/ubuntu/luckfox-pico/tools/linux/toolchain/arm-rockchip830-linux-uclibcgnueabihf/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd ~/luckfox-pico
ln -rfs project/cfg/BoardConfig_IPC/BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk .BoardConfig.mk
./build.sh clean
ln -rfs project/cfg/BoardConfig_IPC/BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk .BoardConfig.mk
./build.sh
```

The clean step is for the initial configuration switch/clean rebuild, not every
small overlay edit. It removes build outputs and `.BoardConfig.mk`, which is why
the selection link is recreated afterward. Copy any needed old outputs elsewhere
before cleaning. Add the public key before building.

### 5.2 Image formats

| Output | Use |
|---|---|
| `env.img`, `idblock.img`, `uboot.img`, `boot.img`, `userdata.img`, `rootfs.img` | Individual partition components |
| `update.img` | Rockchip firmware container for compatible firmware-aware tools |
| `sd_update.img` | Combined SD disk image for a raw whole-card image writer |

The SDK already generates the combined SD image when `RK_BOOT_MEDIUM=sd_card`;
the VPN implementation did not introduce that packaging step.

**Do not write `update.img` to the whole card with a raw image writer.** Do not
copy an image file onto a formatted card and expect that to install the system.

### 5.3 SocToolKit v2.2 SD Boot workflow

1. Select **SDTool -> SD Boot**, not SD Upgrade.
2. Verify the destination disk by capacity and by removing/reinserting the card
   reader. Do not trust an ambiguous device name alone.
3. Under **Boot Files...**, load the six individual partition images listed above.
4. Do not add `update.img` or `sd_update.img` alongside the individual components.
5. Check that all six entries, including rootfs, appear, then use **Create SD**.
6. Safely eject the card, insert it into the unpowered board, then apply power.

The recorded SocToolKit run submitted all six images at the expected Mini VPN
sector offsets: `0`, `64`, `1088`, `1600`, `67136`, and `591424`.
Its `-t emmc` conversion argument is not by itself a wrong-target error: the SDK
also uses the emmc block-storage mode for SD update-script generation.
The command log alone did not provide read-back verification.

Alternatively, write `sd_update.img` directly to the whole card with a raw image
writer such as Win32 Disk Imager. These are alternative workflows, not consecutive
steps. Both must be treated as destructive.

Later selective updates can preserve userdata if only the required boot/rootfs
partitions are rewritten and the layout is unchanged. Verify the device/partition
mapping and unmount affected filesystems first; do not overwrite a running rootfs.

## 6. Router and first-login setup

Configure the router:

1. Reserve **192.168.0.10** for MAC **d6:af:ce:d0:c4:c3**. The board still uses DHCP;
   this is not a static-address change in the rootfs overlay.
2. Forward **WAN UDP 51820 -> 192.168.0.10 UDP 51820**.
3. Keep DDNS for `psykey.webhop.me` updated with the home public IPv4.
4. Do not forward TCP 22. Review IPv6 exposure independently; IPv4 NAT rules do
   not protect a globally routed IPv6 address.
5. Free No-IP hostnames may require periodic confirmation.

After key login works:

```sh
passwd
```

Set a strong, unique root password for console/USB rescue. The stock password is
public knowledge and may return after a full reflash; changing it does not enable
LAN password authentication. Do not put the new password in git.

## 7. Board functionality checklist

Commands in this section run **on the board** unless explicitly marked otherwise.
Keep the working SSH session or ADB available while testing.

### 7.1 Storage, time, and kernel health

```sh
df -h / /userdata
mount
free -m
date
dmesg | tail -n 80
tail -n 80 /var/log/messages
```

Check that:

- `/` is the fixed-size ext4 root filesystem and `/userdata` is a separate mount.
- There is free space on both filesystems and no ongoing out-of-memory failures.
- Time has synchronized before relying on backup dates or handshake timestamps.
  The board has no battery-backed RTC in this setup; early January 1 timestamps
  and initial NTP clock-unsynchronized messages can occur during boot.
- SD-card errors are not recurring. An MMC timeout appeared in the bring-up log.
  Repeated timeouts, I/O errors, or ext4 errors warrant checking card quality,
  power, contacts, and storage health even if the system currently works.

### 7.2 Ethernet, DHCP, MAC, and LEDs

```sh
cat /sys/class/net/eth0/address
cat /sys/class/net/eth0/carrier
cat /sys/class/net/eth0/speed
ip -4 addr show eth0
ip -4 route
ping -c 3 192.168.0.1
```

Expected with the current router:

- MAC `d6:af:ce:d0:c4:c3`, including after a reboot.
- Carrier `1`, speed `100` with a compatible 100 Mbps link partner.
- Address `192.168.0.10/24`, and a default route via `192.168.0.1`.
- Gateway reachable, assuming it answers ICMP.

For the added GPIO link/activity LEDs:

```sh
cat /sys/class/leds/eth_link/trigger
cat /sys/class/leds/eth_link/device_name
cat /sys/class/leds/eth_link/link
cat /sys/class/leds/eth_act/device_name
cat /sys/class/leds/eth_act/rx
cat /sys/class/leds/eth_act/tx
```

Expect the selected trigger to be `netdev`, both device names to be `eth0`, and
the relevant link/rx/tx attributes to be `1`. Link indication should follow cable
connection, and activity should respond to traffic. GPIO LEDs are distinct from
the switch's physical-port LEDs. UART3/UART4 must remain disabled because those
pins are reused for LEDs.

The onboard red activity LED alone is not proof of success or failure.

### 7.3 USB/ADB rescue

On the PC:

```sh
adb devices
adb shell
```

The firmware includes ADB and USB-RNDIS. If no USB device enumerates in Windows
Device Manager, changing the ADB driver alone will not fix that: check boot
progress, a known-good data cable, and power.

The stock USB script initially configures `172.32.0.70`; the later USB helper
sets the intended rescue address `172.32.0.93`. If boot stalls between these
scripts, the final address may not yet be present. USB SSH requires a suitably
configured PC-side RNDIS interface; no automatic host setup is implied here.

USB initialization follows WireGuard and SSH host-key generation in the boot
sequence. A stall earlier in init can therefore prevent USB from appearing.
First boot can take longer than later boots. Use serial logs to diagnose a real
stall rather than treating every LED change as a kernel panic.

### 7.4 SSH behavior

Verify the ownership/modes in section 3 and perform a key login from the PC.
For a deliberate negative test, use a separate PC terminal:

```sh
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password root@192.168.0.10
```

LAN password authentication should be refused. The USB exception applies only to
connections targeting local address `172.32.0.93`; it is not a LAN exception.

After a failed attempt, inspect:

```sh
tail -n 60 /var/log/messages
```

`logread` is not installed in the tested image, so use the file log.
Do not disable OpenSSH's ownership checks to work around an incorrectly owned key.

### 7.5 WireGuard and firewall

```sh
sysctl net.ipv4.ip_forward
ip -4 addr show wg0
wg show
iptables -S
iptables -t nat -S
iptables -t mangle -S
```

Expected:

- IPv4 forwarding is `1`.
- `wg0` has `10.6.0.1/24` and listens on UDP 51820.
- INPUT and FORWARD default policies are DROP.
- Input permits the configured WireGuard UDP port on eth0 and SSH on eth0/wg0.
- Forwarding permits `wg0 -> eth0` and established/related return traffic.
- NAT MASQUERADE covers `10.6.0.0/24` leaving eth0.
- TCP SYN forwarding has MSS clamping.
- Client-to-client forwarding is not explicitly allowed by default.

For a startup failure:

```sh
cat /var/log/wg-quick.log
```

Do not casually restart the firewall or change rules through your only remote
connection. Runtime firewall edits are not automatically saved; if intentional:

```sh
/etc/init.d/S35iptables save
```

`wg show` normally hides private keys. In contrast, configuration files, QR codes,
backups, and `wg show wg0 dump` can expose secrets. Do not post them publicly.

### 7.6 Create and import one test client

```sh
pivpn help
pivpn add -n phone
pivpn list
pivpn qrcode phone
```

If `phone` already exists, use its existing QR code or choose another unique name.
Scan using the official WireGuard phone app. The generated configuration contains:

- An allocated client IPv4 address.
- The server's public key and the client's private/preshared keys.
- Endpoint `psykey.webhop.me:51820`.
- Quad9 DNS, MTU 1420, keepalive 25 seconds.
- Full-tunnel AllowedIPs `0.0.0.0/0, ::/0`.

The QR code is a credential. Anyone who obtains it can use that client identity.
Do not include it in screenshots, logs, or support messages.

### 7.7 Test from mobile data, not home Wi-Fi

1. Turn off Wi-Fi on the phone and use mobile data.
2. Activate the WireGuard tunnel.
3. On the board, run:

   ```sh
   wg show
   pivpn clients
   ```

4. Confirm a recent handshake and increasing receive/transmit counters while the
   phone generates traffic.
5. Open an IP-check website: the public **IPv4** must match the home's public IPv4,
   not the mobile operator's.
6. Browse several sites to exercise DNS and normal TCP/HTTPS traffic.
7. Run a DNS-leak test: expect Quad9 infrastructure rather than mobile-operator
   resolvers. Browser/application encrypted DNS settings can override system DNS,
   so account for those settings when interpreting results.
8. Run an IPv6 connectivity test. This design routes `::/0` into an IPv4-only VPN
   to prevent direct client IPv6 escape. Working public IPv6 through this server
   is not expected; IPv6-only destinations may not work.
9. Test SSH to `root@10.6.0.1` from a client with the appropriate private SSH key.

Home Wi-Fi is not a substitute for this test: a router may lack NAT loopback.
The phone app displaying "active" only means its local tunnel is enabled, not
that a handshake or usable traffic has occurred.

### 7.8 Disable, enable, remove, and reboot

While generating fresh traffic on the phone:

```sh
pivpn off phone -y
pivpn list
```

The client should be marked disabled and traffic should stop, even if the app
still displays an enabled tunnel. Re-enable:

```sh
pivpn on phone
```

Confirm traffic resumes; toggle the phone tunnel if necessary.

For a disposable test client only:

```sh
pivpn remove testclient -y
```

Removal deletes its stored profile/keys and peer entry; do not remove the working
phone client unless you intend to revoke it.

After other checks pass, reboot:

```sh
reboot
```

Reconnect, then check:

```sh
cat /sys/class/net/eth0/address
ip -4 addr show eth0
wg show
pivpn list
```

The MAC and reserved LAN address should be unchanged; stored clients should remain,
and the phone should reconnect without importing a new profile.

### 7.9 Optional throughput test

Run an iperf3 server on the board:

```sh
iperf3 -s
```

From a connected VPN client with iperf3 installed:

```sh
iperf3 -c 10.6.0.1
iperf3 -c 10.6.0.1 -R
```

The default INPUT policy does not allow iperf3's TCP port 5201. For this test only,
use a second board session to add a temporary tunnel-only rule:

```sh
iptables -I INPUT 1 -i wg0 -p tcp --dport 5201 -j ACCEPT
```

After the test, remove that exact rule and stop iperf3 with Ctrl+C:

```sh
iptables -D INPUT -i wg0 -p tcp --dport 5201 -j ACCEPT
```

Do not save the temporary rule or forward this port on the router. Record mobile
link quality, CPU load, and direction when comparing results. A NEON on/off
comparison requires separate kernel builds under otherwise comparable conditions.

## 8. Backup, PC download, and integrity verification

### 8.1 Create the archive on the board

```sh
pivpn backup
```

Example output:

```text
::: Backup created: /userdata/vpn-backup/pivpnbackup-20261022-100716.tgz
```

The archive contains `/userdata/wireguard` and `/etc/pivpn`, including private keys.
It is not a whole-system backup: root's authorized keys, SSH host keys, root
password changes, and arbitrary firewall edits are not included.

Backup directory mode is 0700 and archive mode is 0600. The newest five named
archives are retained. Dates and filename ordering depend on correct NTP time.
Two invocations in the same second use the same filename, so do not rely on those
being separate backups.

### 8.2 Run the download on the PC, not the board

The printed scp hint is intended for the **PC's shell**. Running it from the board
makes the board SSH back into itself; it normally lacks your private login key and
fails with `Permission denied (publickey)`. Do not copy the private key onto the
board to work around this.

In Windows PowerShell, using PuTTY PSCP and the matching private key:

```powershell
Set-Location D:\Temp\Luckfox
.\pscp.exe -i ".\myPrivateKey.ppk" root@192.168.0.10:/userdata/vpn-backup/pivpnbackup-20261022-100716.tgz .
```

Use the filename actually printed by your backup command. Enter the private-key
passphrase when prompted. Verify the server host-key fingerprint against a trusted
connection before accepting a new host key.

The tested board's ED25519 host-key fingerprint was:

```text
SHA256:uGB6aJPgBVv/m9wEpkdj/hyiCueDNIUBAW6y7XU4M/Y
```

This is the **server identity**, not the authorized client RSA-key fingerprint.
A full rootfs reflash may generate new host keys. Investigate unexpected changes;
do not blindly accept a changed fingerprint.

PSCP 0.85 successfully transferred the archive using SFTP. Success indicators were:

```text
Offer of public key accepted
Access granted
Using SFTP
100%
Session sent command exit status 0
```

WinSCP is an alternative: select SFTP, host `192.168.0.10`, user `root`, and the
same private `.ppk`, then download the archive from `/userdata/vpn-backup`.

For transfer troubleshooting:

```powershell
.\pscp.exe -V
.\pscp.exe -v -i ".\myPrivateKey.ppk" root@192.168.0.10:/userdata/vpn-backup/pivpnbackup-20261022-100716.tgz .
```

A key rejection alone does not prove an old client or wrong key; check the server
log immediately after the attempt. Never share private key contents.

### 8.3 Compare hashes and inspect archive structure

On the board:

```sh
sha256sum /userdata/vpn-backup/pivpnbackup-20261022-100716.tgz
gzip -t /userdata/vpn-backup/pivpnbackup-20261022-100716.tgz
gzip -dc /userdata/vpn-backup/pivpnbackup-20261022-100716.tgz | tar -tf -
```

In Windows PowerShell:

```powershell
Get-FileHash .\pivpnbackup-20261022-100716.tgz -Algorithm SHA256
```

The SHA-256 values must match, ignoring letter case. This succeeded for the recorded
download. A roughly 1 kB compressed archive is plausible for a small number of
profiles, but size alone is not an integrity check.

Matching hashes confirm the transfer, not that a restore has been tested. Store
the archive in protected off-device storage; the backup command does not encrypt
it. Do not commit it or upload it to a public support service.

## 9. Restore and firmware updates

Restore only an archive you trust and keep a working LAN/USB management path.
Restoring stops/restarts WireGuard, so do not rely on the tunnel as your only
connection.

From Windows PowerShell, upload a backup:

```powershell
.\pscp.exe -i ".\myPrivateKey.ppk" .\pivpnbackup-20261022-100716.tgz root@192.168.0.10:/userdata/
```

On the board:

```sh
pivpn restore /userdata/pivpnbackup-20261022-100716.tgz
wg show
pivpn list
```

Read the confirmation before proceeding. Restore checks expected archive paths,
extracts to a temporary directory, keeps the previous WireGuard tree at
`/userdata/wireguard.prev`, fixes restored data permissions, and brings up wg0.
These checks are not a reason to accept an untrusted archive.

Re-test the phone from mobile data. Restoring the same server/client keys should
allow existing client profiles to work without re-importing them.

For a meaningful recovery test, use a spare card if available. Before any full
reflash, create/download/hash-check the backup. Re-import the authorized SSH public
key into the new image as needed; the VPN backup does not preserve it.

Do not assume `/userdata/wireguard.prev` is a complete rollback: settings under
`/etc/pivpn` are also overwritten during restore. Keep the original off-device
backup regardless of that previous-state directory.

## 10. Troubleshooting reference and remaining cautions

| Symptom | Evidence to collect / next check |
|---|---|
| No DHCP lease | Link/carrier, fixed MAC, router reservation, cabling, dhcpcd messages |
| No USB device in Device Manager | Data cable/power, boot progress, card layout, then serial boot log |
| Rootfs grows unexpectedly or boot stalls with old layout | Confirm rebuilt images actually contain `6G(rootfs)` and recreate the card after backing up |
| SSH says bad ownership or modes | Correct root ownership plus 0700 directories and 0600 authorized_keys |
| SSH key is refused otherwise | Compare key fingerprint; inspect PuTTY/PSCP verbose output and `/var/log/messages` |
| SSH reports RSA/SHA-1 not accepted | Update client; do not enable obsolete signatures as the default fix |
| No WireGuard handshake | Phone on mobile data, DDNS public IPv4, router UDP forward, ISP/public IPv4 reachability |
| Handshake but no internet | IPv4 forwarding, NAT/filter rules, routes, DNS, then MTU if traffic selectively stalls |
| App says active but no traffic | Check real handshake/counters; local tunnel activation is not proof of connectivity |
| Incorrect archive/handshake dates | NTP synchronization and clock/timezone; early boot starts without a valid RTC |
| Repeated MMC/ext4 errors | Preserve data; investigate card, contacts, and power rather than repeatedly reflashing |

Further cautions:

- The firewall in this implementation covers IPv4 only. Review LAN/WAN IPv6
  access separately, even though SSH remains key-only.
- The CMA reservation is 1 MiB instead of the stock camera-oriented 24 MiB.
  If actual driver errors implicate CMA, investigate and consider 4 MiB; do not
  diagnose every boot problem as CMA without logs.
- WireGuard key generation and SSH host-key generation depend on the kernel RNG.
  Startup timing on the board is not reproduced by mocked userspace tests.
- Use a 3.3 V TTL USB-to-UART adapter for serial diagnostics: common ground,
  crossed TX/RX, no adapter power pin connected. Confirm the board's debug-UART
  pins and baud rate before connecting; do not use RS-232 voltage levels.
- The SD card remains a single point of failure. Keep verified off-device backups
  and consider a quality endurance card.
