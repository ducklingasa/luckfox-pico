#!/usr/bin/python3
"""Shared bounded validation/extraction for VPN backups, never extract tar links."""

import base64
import gzip
import ipaddress
from pathlib import Path
import re
import shlex
import sys
import tarfile
import zlib

NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,14}"
MAX_EXPANDED = 32 * 1024 * 1024
MAX_FILE = 1024 * 1024
DIRECTORIES = {"userdata/wireguard", "userdata/wireguard/keys",
               "userdata/wireguard/configs", "etc/pivpn", "etc/pivpn/wireguard"}


def key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


def number(value, lower, upper):
    return value.isascii() and value.isdigit() and lower <= int(value) <= upper


def addresses(value, network=False):
    try:
        for item in value.split(","):
            if network:
                ipaddress.ip_network(item.strip(), strict=False)
            else:
                ipaddress.ip_interface(item.strip())
        return True
    except ValueError:
        return False


def valid_settings(text):
    values = {}
    allowed = {"IPv4dev", "pivpnDEV", "pivpnPORT", "pivpnHOST", "pivpnNET",
               "subnetClass", "pivpnDNS1", "pivpnDNS2", "ALLOWED_IPS", "pivpnMTU",
               "pivpnPERSISTENTKEEPALIVE", "BACKUP_DIR"}
    for line in text.splitlines():
        # These characters have shell meaning even inside double quotes.
        if any(c in line for c in ("$", "`", "\\", ";", "\x00")):
            raise ValueError("unsafe settings")
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if len(words) != 1 or "=" not in words[0]:
            raise ValueError("invalid settings")
        name, value = words[0].split("=", 1)
        if name not in allowed or name in values:
            raise ValueError("unexpected setting")
        values[name] = value
    if set(values) != allowed:
        raise ValueError("incomplete settings")
    if (values["IPv4dev"] != "eth0" or values["pivpnDEV"] != "wg0" or
            values["BACKUP_DIR"] != "/userdata/vpn-backup" or values["subnetClass"] != "24" or
            not number(values["pivpnPORT"], 1, 65535) or not number(values["pivpnMTU"], 576, 9000) or
            not number(values["pivpnPERSISTENTKEEPALIVE"], 0, 65535) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", values["pivpnHOST"]) or
            not addresses(values["ALLOWED_IPS"], network=True)):
        raise ValueError("unsupported settings")
    ipaddress.IPv4Network(values["pivpnNET"] + "/24")
    ipaddress.ip_address(values["pivpnDNS1"])
    if values["pivpnDNS2"]:
        ipaddress.ip_address(values["pivpnDNS2"])


def valid_wg(text):
    section = None
    fields = set()
    has_interface = False
    def complete():
        required = {"PrivateKey", "Address"} if section == "[Interface]" else {"PublicKey", "AllowedIPs"}
        if section is not None and not required.issubset(fields):
            raise ValueError("incomplete WireGuard section")
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#[disabled] "):
            line = line[len("#[disabled] "):]
        if not line or line.startswith("#"):
            continue
        if line in ("[Interface]", "[Peer]"):
            complete()
            if line == "[Interface]":
                if has_interface:
                    raise ValueError("duplicate interface")
                has_interface = True
            section = line
            fields = set()
            continue
        name, sep, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or section is None:
            raise ValueError("invalid WireGuard configuration")
        interface = {"PrivateKey", "Address", "ListenPort", "MTU", "DNS"}
        peer = {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}
        if name in fields or name not in (interface if section == "[Interface]" else peer):
            raise ValueError("unsupported WireGuard directive")
        fields.add(name)
        if name.endswith("Key"):
            valid = key(value)
        elif name in ("Address", "DNS", "AllowedIPs"):
            valid = addresses(value, network=(name == "AllowedIPs"))
        elif name == "Endpoint":
            valid = re.fullmatch(r"[A-Za-z0-9.-]+:[0-9]{1,5}", value) is not None
        else:
            valid = number(value, 0, 65535)
        if not valid:
            raise ValueError("invalid WireGuard value")
    complete()
    if not has_interface:
        raise ValueError("missing interface section")


def valid_file(name, data):
    text = data.decode("utf-8")
    if "\x00" in text:
        raise ValueError("NUL in configuration")
    relative = name.removeprefix("userdata/wireguard/")
    if name == "etc/pivpn/wireguard/setupVars.conf":
        valid_settings(text)
    elif relative == "wg0.conf" or re.fullmatch(r"configs/" + NAME + r"\.conf", relative):
        valid_wg(text)
    elif relative in ("server_priv", "server_pub") or re.fullmatch(r"keys/" + NAME + r"_(priv|pub|psk)", relative):
        if not key(text.strip()):
            raise ValueError("invalid key file")
    elif relative == "configs/clients.txt":
        names, ips = set(), set()
        for line in text.splitlines():
            fields = line.split()
            if len(fields) != 4:
                raise ValueError("invalid client metadata")
            client, public, epoch, address = fields
            ipaddress.IPv4Address(address)
            if (not re.fullmatch(NAME, client) or not key(public) or
                    not number(epoch, 0, 2**63 - 1) or client in names or address in ips):
                raise ValueError("invalid client metadata")
            names.add(client)
            ips.add(address)
    else:
        raise ValueError("unexpected backup file")


class BoundedReader:
    def __init__(self, source):
        self.source, self.count = source, 0

    def read(self, size=-1):
        data = self.source.read(min(size if size >= 0 else 65536, 65536))
        self.count += len(data)
        if self.count > MAX_EXPANDED:
            raise ValueError("archive expands beyond limit")
        return data

    def exact(self, size):
        pieces = []
        remaining = size
        while remaining:
            data = self.read(remaining)
            if not data:
                raise ValueError("truncated tar archive")
            pieces.append(data)
            remaining -= len(data)
        return b"".join(pieces)


def validate(path, destination=None):
    seen = set()
    try:
        with gzip.open(path, "rb") as compressed:
            bounded = BoundedReader(compressed)
            while True:
                header = bounded.exact(512)
                if header == b"\0" * 512:
                    if bounded.exact(512) != b"\0" * 512:
                        raise ValueError("invalid tar terminator")
                    break
                member = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="strict")
                # Reject extension headers before the tar library can buffer a
                # hostile PAX/GNU payload. This appliance needs only short names.
                if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                    raise ValueError("unsupported archive member type")
                name = member.name
                if name.startswith("./"):
                    name = name[2:]
                name = name.rstrip("/")
                if (name in seen or len(seen) >= 1024 or
                        any(part in ("", ".", "..") for part in name.split("/"))):
                    raise ValueError("invalid or duplicate archive path")
                seen.add(name)
                if member.isdir() and name in DIRECTORIES and member.size == 0:
                    if destination is not None:
                        (destination / name).mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                if not member.isfile() or not 0 <= member.size <= MAX_FILE:
                    raise ValueError("unsupported archive member")
                data = bounded.exact(member.size)
                padding = bounded.exact((-member.size) % 512)
                if any(padding):
                    raise ValueError("nonzero tar padding")
                valid_file(name, data)
                if destination is not None:
                    target = destination / name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with target.open("xb") as output:
                        output.write(data)
                    target.chmod(0o600)
            # Validate gzip CRC/trailer and reject hidden concatenated tar content.
            while True:
                tail = bounded.read(65536)
                if not tail:
                    break
                if any(tail):
                    raise ValueError("unexpected data after tar terminator")
        required = {"userdata/wireguard/wg0.conf", "userdata/wireguard/configs/clients.txt",
                    "userdata/wireguard/server_priv", "userdata/wireguard/server_pub",
                    "etc/pivpn/wireguard/setupVars.conf"}
        if not required.issubset(seen):
            raise ValueError("incomplete VPN backup")
    except (OSError, EOFError, tarfile.TarError, UnicodeError, zlib.error) as error:
        raise ValueError("invalid VPN archive") from error


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (2, 3):
            raise ValueError("usage: archive.py <archive> [private-empty-destination]")
        validate(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) == 3 else None)
    except ValueError:
        print("::: Invalid or unsupported VPN backup archive", file=sys.stderr)
        sys.exit(1)
