#!/usr/bin/python3
"""Short-lived BusyBox CGI backend; no third-party Python dependencies."""

import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse

AUTH = Path("/userdata/webui")
RUN = Path("/run/webui")
WG = Path("/userdata/wireguard")
BACKUPS = Path("/userdata/vpn-backup")
SETTINGS = Path("/etc/pivpn/wireguard/setupVars.conf")
SESSION_SECONDS = 1800
ITERATIONS = 600000
UPLOAD_LIMIT = 16 * 1024 * 1024
COOKIE = "vpn_session"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,14}\Z")
BACKUP = re.compile(r"pivpnbackup-[0-9]{8}-[0-9]{6}(?:-[1-9][0-9]*)?\.tgz\Z")
SID = re.compile(r"[0-9a-f]{64}\Z")
HERE = Path(__file__).resolve().parent


class APIError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def fail(status, code, message):
    raise APIError(status, code, message)


def uptime():
    return float(Path("/proc/uptime").read_text().split()[0])


@contextlib.contextmanager
def lock(path, shared=False):
    with open(path, "a", encoding="ascii") as handle:
        try:
            fcntl.flock(handle, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            fail(409, "busy", "Another operation is running. Please retry.")
        yield


def atomic(path, text):
    fd, name = tempfile.mkstemp(prefix=".new-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def prepare():
    if os.geteuid() != 0 or not os.path.ismount("/userdata"):
        raise RuntimeError("root and mounted /userdata are required")
    os.umask(0o077)
    if len(hashlib.pbkdf2_hmac("sha256", b"probe", b"probe", 1)) != 32:
        raise RuntimeError("password hashing is unavailable")
    for path in (AUTH, RUN, RUN / "sessions", BACKUPS):
        if path.is_symlink():
            raise RuntimeError("private storage must not be a symlink")
        path.mkdir(mode=0o700, exist_ok=True)
        os.chown(path, 0, 0)
        path.chmod(0o700)
    with lock(RUN / "auth.lock"):
        for name in ("auth.conf", "setup-token"):
            path = AUTH / name
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError("invalid credential storage")
                os.chown(path, 0, 0)
                path.chmod(0o600)
        if not (AUTH / "auth.conf").exists():
            for sid in clean_sessions(uptime()):
                (RUN / "sessions" / sid).unlink()
            if not (AUTH / "setup-token").exists():
                atomic(AUTH / "setup-token", secrets.token_hex(32) + "\n")
        if (AUTH / "auth.conf").exists():
            (AUTH / "setup-token").unlink(missing_ok=True)


def session_id(environ):
    found = []
    for part in environ.get("HTTP_COOKIE", "").split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == COOKIE:
            found.append(value)
    return found[0] if len(found) == 1 and SID.fullmatch(found[0]) else None


def clean_sessions(now):
    live = []
    for path in (RUN / "sessions").iterdir():
        if not SID.fullmatch(path.name) or not path.is_file() or path.is_symlink():
            raise RuntimeError("invalid session storage")
        issued = float(path.read_text())
        if not 0 <= now - issued < SESSION_SECONDS:
            path.unlink()
        else:
            live.append(path.name)
    return live


def authenticated(environ):
    with lock(RUN / "auth.lock"):
        if not (AUTH / "auth.conf").is_file():
            return False
        sid = session_id(environ)
        return sid is not None and sid in clean_sessions(uptime())


def check_origin(environ):
    host = environ.get("HTTP_HOST", "")
    if not re.fullmatch(r"[0-9.]+:8080", host):
        fail(403, "origin", "Use the device LAN IPv4 address and port 8080.")
    try:
        ipaddress.IPv4Address(host.rsplit(":", 1)[0])
    except ipaddress.AddressValueError:
        fail(403, "origin", "Invalid request host.")
    if environ.get("HTTP_ORIGIN") != "http://" + host or environ.get("HTTP_X_VPN_UI") != "1":
        fail(403, "origin", "A same-origin browser request is required.")
    if environ.get("HTTP_SEC_FETCH_SITE", "same-origin") not in ("same-origin", "none"):
        fail(403, "origin", "Cross-origin requests are not allowed.")


def length(environ, maximum):
    value = environ.get("CONTENT_LENGTH", "")
    if not re.fullmatch(r"0|[1-9][0-9]{0,8}", value):
        fail(411, "length", "A valid Content-Length is required.")
    size = int(value)
    if size > maximum:
        fail(413, "too_large", "Request body exceeds the allowed size.")
    return size


def parse_fields(raw, expected):
    if not raw:
        if expected:
            fail(400, "fields", "Missing request fields.")
        return {}
    if len(raw) > 4096:
        fail(413, "too_large", "Request fields exceed the allowed size.")
    if re.search(r"%(?![0-9a-fA-F]{2})", raw):
        fail(400, "encoding", "Malformed URL encoding.")
    try:
        pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True, strict_parsing=True,
                                      encoding="utf-8", errors="strict", max_num_fields=8)
    except (ValueError, UnicodeError):
        fail(400, "fields", "Malformed request fields.")
    fields = {}
    for key, value in pairs:
        if key in fields or key not in expected or any(ord(c) < 32 or ord(c) == 127 for c in value):
            fail(400, "fields", "Unknown, duplicate, or invalid request field.")
        fields[key] = value
    if set(fields) != set(expected):
        fail(400, "fields", "Missing request fields.")
    return fields


def form(environ, stream, expected):
    if environ.get("QUERY_STRING"):
        fail(400, "fields", "POST requests must not contain a query string.")
    if environ.get("CONTENT_TYPE", "").split(";")[0] != "application/x-www-form-urlencoded":
        fail(415, "content_type", "Expected URL-encoded form data.")
    # BusyBox omits CONTENT_LENGTH from CGI environment when the length is zero.
    size = 0 if not expected and not environ.get("CONTENT_LENGTH") else length(environ, 4096)
    data = stream.read(size)
    if len(data) != size:
        fail(400, "truncated", "Request body was truncated.")
    try:
        return parse_fields(data.decode("ascii"), expected)
    except UnicodeError:
        fail(400, "encoding", "URL-encode non-ASCII input.")


def rate_limit(now):
    path = RUN / "attempts"
    attempts = json.loads(path.read_text()) if path.exists() else []
    attempts = [t for t in attempts if 0 <= now - t < 60]
    if len(attempts) >= 5:
        fail(429, "rate_limit", "Too many login/setup attempts. Wait one minute.")
    attempts.append(now)
    atomic(path, json.dumps(attempts))


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS).hex()


def login(action, fields, environ):
    with lock(RUN / "auth.lock"):
        if action == "logout":
            sid = session_id(environ)
            if sid:
                (RUN / "sessions" / sid).unlink(missing_ok=True)
            return {"ok": True}, [( "Set-Cookie",
                COOKIE + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")]
        configured = (AUTH / "auth.conf").exists()
        if action == "setup" and configured:
            fail(409, "configured", "Setup is complete. Please log in.")
        if action == "login" and not configured:
            fail(403, "setup_required", "Complete token-gated setup first.")
        now = uptime()
        rate_limit(now)
        password = fields["password"]
        if action == "setup":
            token = (AUTH / "setup-token").read_text().strip()
            if not hmac.compare_digest(fields["token"].encode(), token.encode()):
                fail(403, "credentials", "Invalid setup token.")
            if (not 8 <= len(password) <= 32 or
                    not re.search(r"[a-z]", password) or
                    not re.search(r"[A-Z]", password) or
                    not re.search(r"[0-9]", password) or
                    password.lower() in {"passwordpassword", "changemechangeme", "luckfoxluckfoxluckfox"} or
                    password != fields["password_confirm"]):
                fail(400, "password", "Use a unique 8-32 character password with a lowercase letter, an uppercase letter, and a number; enter it identically twice.")
            salt = secrets.token_bytes(32)
            for sid in clean_sessions(now):
                (RUN / "sessions" / sid).unlink()
            atomic(AUTH / "auth.conf", json.dumps({
                "algorithm": "pbkdf2-sha256", "iterations": ITERATIONS,
                "salt": salt.hex(), "hash": password_hash(password, salt)}))
            (AUTH / "setup-token").unlink()
            return {"ok": True}, []
        verifier = json.loads((AUTH / "auth.conf").read_text())
        if verifier["algorithm"] != "pbkdf2-sha256" or verifier["iterations"] != ITERATIONS:
            raise RuntimeError("unsupported password verifier")
        if len(password) > 128 or not hmac.compare_digest(
                password_hash(password, bytes.fromhex(verifier["salt"])), verifier["hash"]):
            fail(401, "credentials", "Invalid password.")
        live = clean_sessions(now)
        if len(live) >= 8:
            fail(429, "sessions", "Session limit reached. Wait for a session to expire.")
        sid = secrets.token_hex(32)
        atomic(RUN / "sessions" / sid, str(uptime()))
        return {"ok": True}, [("Set-Cookie", COOKIE + "=" + sid + "; Path=/; HttpOnly; SameSite=Strict")]


def command(args, timeout=30):
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, start_new_session=True) as process:
        try:
            output, _ = process.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, APIError):
            # Stop the operation's entire subprocess tree, not just its shell.
            # A timeout can still leave partially changed persistent VPN state.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            fail(504, "timeout", "The operation timed out; refresh status before retrying.")
        if process.returncode:
            fail(500, "command", "The operation failed. Refresh status and check the device over SSH.")
        return output


def settings():
    result = {}
    for line in SETTINGS.read_text().splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if len(words) != 1 or "=" not in words[0]:
            raise RuntimeError("invalid server settings")
        key, value = words[0].split("=", 1)
        result[key] = value
    return result


def wg_running():
    return Path("/sys/class/net/wg0").exists()


def led_state():
    enabled, disabled = 0, 0
    for name in ("eth_link", "eth_act", "work"):
        path = Path("/sys/class/leds") / name
        if not (path / "trigger").exists():
            return "unavailable"
        try:
            selected = re.search(r"\[([^]]+)\]", (path / "trigger").read_text())
            trigger = selected[1] if selected else ""
            if trigger == "none" and (path / "brightness").read_text().strip() == "0":
                disabled += 1
            elif name == "work" and trigger == "activity":
                enabled += 1
            elif name != "work" and trigger == "netdev":
                expected = {"link": "1", "rx": "0", "tx": "0"} if name == "eth_link" else {
                    "link": "0", "rx": "1", "tx": "1"}
                if ((path / "device_name").read_text().strip() == "eth0" and
                        all((path / attr).read_text().strip() == value for attr, value in expected.items())):
                    enabled += 1
        except (FileNotFoundError, PermissionError):
            return "unavailable"
    return "enabled" if enabled == 3 else "disabled" if disabled == 3 else "mixed"


def metrics():
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        mem[key] = int(value.split()[0]) * 1024
    cpu = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
    networks = {}
    for name in ("eth0", "wg0"):
        root = Path("/sys/class/net") / name / "statistics"
        networks[name] = ({"rx": int((root / "rx_bytes").read_text()),
                           "tx": int((root / "tx_bytes").read_text())} if root.exists() else None)
    temperatures = []
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        try:
            temperatures.append({"name": (zone / "type").read_text().strip(),
                                 "celsius": int((zone / "temp").read_text()) / 1000})
        except (FileNotFoundError, PermissionError, ValueError):
            temperatures.append({"name": zone.name, "celsius": None})
    storage = []
    for path in ("/", "/userdata"):
        usage = shutil.disk_usage(path)
        storage.append({"path": path, "total": usage.total, "used": usage.used, "free": usage.free})
    return {"uptime": uptime(), "load": list(os.getloadavg()),
            "cpu": {"total": sum(cpu), "idle": cpu[3] + cpu[4]},
            "memory": {"total": mem["MemTotal"], "available": mem.get("MemAvailable"),
                       "swap_total": mem["SwapTotal"], "swap_free": mem["SwapFree"]},
            "storage": storage, "temperatures": temperatures, "networks": networks}


def status():
    with lock(Path("/run/pivpn.lock"), shared=True):
        config = settings()
        if not (WG / "wg0.conf").is_file():
            fail(503, "not_ready", "WireGuard configuration is unavailable.")
        values = {key: config.get(key) for key in
                  ("pivpnHOST", "pivpnPORT", "pivpnNET", "subnetClass",
                   "pivpnDNS1", "pivpnDNS2", "pivpnMTU", "ALLOWED_IPS")}
        running = wg_running()
        address = None
        listen_port = int(config["pivpnPORT"])
        if running:
            listen_port = int(command(["wg", "show", "wg0", "listen-port"]).decode().strip())
            output = command(["ip", "-4", "-o", "addr", "show", "dev", "wg0"]).decode().split()
            if "inet" in output:
                address = output[output.index("inet") + 1]
    return {"ok": True, "running": running, "interface": "wg0", "settings": values,
            "address": address, "listen_port": listen_port, "metrics": metrics(), "leds": led_state()}


def clients():
    with lock(Path("/run/pivpn.lock"), shared=True):
        config = (WG / "wg0.conf").read_text()
        rows = (WG / "configs/clients.txt").read_text().splitlines()
        running = wg_running()
        live = {}
        if running:
            # Never request `dump`: it includes private and preshared keys.
            for field in ("latest-handshakes", "transfer", "endpoints"):
                for row in command(["wg", "show", "wg0", field]).decode().splitlines():
                    pub, *values = row.split()
                    live.setdefault(pub, {})[field] = values
        result = []
        for row in rows:
            name, pub, created, address = row.split()
            if not NAME.fullmatch(name):
                raise RuntimeError("invalid client metadata")
            disabled = "#[disabled] ### begin " + name + " ###" in config.splitlines()
            if not disabled and "### begin " + name + " ###" not in config.splitlines():
                raise RuntimeError("client peer missing")
            data = live.get(pub, {})
            handshake = int(data["latest-handshakes"][0]) if "latest-handshakes" in data else None
            result.append({"name": name, "ip": address, "created": int(created),
                           "enabled": not disabled, "handshake": handshake,
                           "recent": handshake is not None and 0 <= time.time() - handshake <= 180 and handshake > 0,
                           "endpoint": data.get("endpoints", [None])[0],
                           "rx": int(data["transfer"][0]) if "transfer" in data else None,
                           "tx": int(data["transfer"][1]) if "transfer" in data else None})
        return {"ok": True, "running": running, "clients": result, "timestamps": "approximate until NTP sync"}


def safe_backup(name):
    if not BACKUP.fullmatch(name):
        fail(400, "filename", "Invalid backup filename.")
    path = BACKUPS / name
    if path.is_symlink() or not path.is_file():
        fail(404, "not_found", "Backup not found.")
    return path


def backup_list():
    rows = []
    for path in BACKUPS.iterdir():
        if BACKUP.fullmatch(path.name) and not path.is_symlink() and path.is_file():
            info = path.stat()
            rows.append({"file": path.name, "size": info.st_size, "modified": info.st_mtime})
    return sorted(rows, key=lambda row: (row["modified"], row["file"]), reverse=True)


def archive_module():
    sys.path.insert(0, "/opt/pivpn")
    import archive
    return archive


def upload(environ, stream):
    if environ.get("QUERY_STRING"):
        fail(400, "fields", "Uploads must not contain a query string.")
    if environ.get("CONTENT_TYPE") != "application/gzip":
        fail(415, "content_type", "Expected application/gzip.")
    size = length(environ, UPLOAD_LIMIT)
    if size == 0:
        fail(400, "empty", "Empty backup.")
    filename = environ.get("HTTP_X_VPN_BACKUP_NAME", "")
    if not BACKUP.fullmatch(filename):
        fail(400, "filename", "Expected an original pivpnbackup-YYYYMMDD-HHMMSS.tgz filename, with an optional numeric suffix.")
    destination = BACKUPS / filename
    if shutil.disk_usage(BACKUPS).free < size + 4 * 1024 * 1024:
        fail(507, "space", "Not enough free space for this upload.")
    with lock(Path("/run/pivpn.lock")):
        if destination.is_symlink() or (destination.exists() and not destination.is_file()):
            fail(400, "filename", "The backup destination is not a regular file.")
        fd, name = tempfile.mkstemp(prefix=".upload-", dir=str(BACKUPS))
        try:
            with os.fdopen(fd, "wb") as target:
                remaining = size
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        fail(400, "truncated", "Upload was truncated.")
                    target.write(chunk)
                    remaining -= len(chunk)
                target.flush()
                os.fsync(target.fileno())
            try:
                archive_module().validate(Path(name))
            except ValueError:
                fail(400, "archive", "Invalid or unsupported VPN backup archive.")
            os.replace(name, destination)
            return {"ok": True, "file": destination.name}
        finally:
            if os.path.exists(name):
                os.unlink(name)


def mutate(action, fields):
    if action == "leds":
        if fields["enabled"] not in ("0", "1"):
            fail(400, "enabled", "enabled must be 0 or 1.")
        result = subprocess.run(["/usr/sbin/system-leds", "on" if fields["enabled"] == "1" else "off"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        state = led_state()
        if result.returncode:
            return {"ok": False, "error": {"code": "leds", "message": "LED operation failed or was partial."},
                    "leds": state}, 500
        return {"ok": True, "leds": state}, 200
    operations = {"client-add": ["add", "-n"], "client-enable": ["on"],
                  "client-disable": ["off"], "client-remove": ["remove"]}
    if action in operations:
        name = fields["name"]
        if not NAME.fullmatch(name):
            fail(400, "name", "Client names must match the existing 1-15 character CLI rule.")
        args = ["/usr/sbin/pivpn"] + operations[action] + [name]
        if action != "client-add":
            args.append("-y")
        command(args, timeout=60)
        return {"ok": True, "live": wg_running()}, 200
    if action == "backup-create":
        # A unique result path is returned by the backward-compatible CLI machine mode.
        output = command(["/usr/sbin/pivpn", "backup", "--web"], timeout=60).decode().strip()
        path = safe_backup(output)
        return {"ok": True, "file": path.name, "modified": path.stat().st_mtime}, 200
    if action == "restore":
        path = safe_backup(fields["file"])
        command(["/usr/sbin/pivpn", "restore", str(path), "-y"], timeout=120)
        return {"ok": True, "message": "Restore complete; wg0 was restarted."}, 200
    if action == "backup-delete":
        with lock(Path("/run/pivpn.lock")):
            path = safe_backup(fields["file"])
            path.unlink()
        return {"ok": True, "file": path.name}, 200
    fail(404, "route", "Unknown operation.")


def response(status_code, data, headers=()):
    body = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode()
    return status_code, "application/json", body, list(headers)


def dispatch(environ, stream):
    route = environ.get("PATH_INFO", "").strip("/")
    method = environ.get("REQUEST_METHOD", "")
    post_fields = {"setup": ("token", "password", "password_confirm"), "login": ("password",),
                   "logout": (), "leds": ("enabled",), "client-add": ("name",),
                   "client-enable": ("name",), "client-disable": ("name",),
                   "client-remove": ("name",), "backup-create": (), "restore": ("file",),
                   "backup-delete": ("file",), "backup-upload": ()}
    get_fields = {"state": (), "app": (), "status": (), "clients": (), "backups": (),
                  "client-config": ("name",), "client-qr": ("name",),
                  "backup-download": ("file",)}
    if route not in post_fields and route not in get_fields:
        fail(404, "route", "Unknown endpoint.")
    if method != ("POST" if route in post_fields else "GET"):
        fail(405, "method", "Unsupported HTTP method.")
    if method == "POST":
        check_origin(environ)
    if route == "state":
        parse_fields(environ.get("QUERY_STRING", ""), ())
        return response(200, {"ok": True, "setup": not (AUTH / "auth.conf").exists()})
    if route not in ("setup", "login", "logout") and not authenticated(environ):
        if route == "app":
            return 302, "text/plain", b"Sign in required.", [("Location", "/")]
        fail(401, "login", "Please log in.")
    if method == "POST":
        if route == "backup-upload":
            return response(200, upload(environ, stream))
        fields = form(environ, stream, post_fields[route])
        if route in ("setup", "login", "logout"):
            data, headers = login(route, fields, environ)
            return response(200, data, headers)
        data, code = mutate(route, fields)
        return response(code, data)
    fields = parse_fields(environ.get("QUERY_STRING", ""), get_fields[route])
    if route == "app":
        return 200, "text/html; charset=utf-8", (HERE / "app.html").read_bytes(), []
    if route == "status":
        return response(200, status())
    if route == "clients":
        return response(200, clients())
    if route == "backups":
        with lock(Path("/run/pivpn.lock"), shared=True):
            return response(200, {"ok": True, "backups": backup_list()})
    if route in ("client-config", "client-qr"):
        name = fields["name"]
        if not NAME.fullmatch(name):
            fail(400, "name", "Invalid client name.")
        with lock(Path("/run/pivpn.lock"), shared=True):
            path = WG / "configs" / (name + ".conf")
            if path.is_symlink() or not path.is_file():
                fail(404, "not_found", "Client profile not found.")
            if route == "client-qr":
                data = command(["qrencode", "-t", "SVG", "-o", "-", "-r", str(path)])
                return 200, "image/svg+xml", data, []
            return 200, "text/plain", path.read_bytes(), [
                ("Content-Disposition", 'attachment; filename="' + name + '.conf"')]
    if route == "backup-download":
        with lock(Path("/run/pivpn.lock"), shared=True):
            path = safe_backup(fields["file"])
            # Opening under the lock preserves this snapshot even if retention unlinks it.
            return 200, "application/gzip", open(path, "rb"), [
                ("Content-Disposition", 'attachment; filename="' + path.name + '"')]
    raise RuntimeError("unhandled endpoint")


def main():
    os.umask(0o077)
    if sys.argv[1:] == ["--init"]:
        prepare()
        return
    def timed_out(signum, frame):
        fail(504, "timeout", "Request timed out. Refresh status before retrying.")
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(150)
    try:
        code, content_type, body, headers = dispatch(os.environ, sys.stdin.buffer)
    except APIError as error:
        if error.status >= 500:
            print("vpn-web: operation failed (" + error.code + ")", file=sys.stderr)
        code, content_type, body, headers = response(error.status, {
            "ok": False, "error": {"code": error.code, "message": error.message}})
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        # Never log exception messages: they can contain settings or request values.
        print("vpn-web: request failed (" + type(error).__name__ + ")", file=sys.stderr)
        code, content_type, body, headers = response(500, {
            "ok": False, "error": {"code": "internal", "message": "Device operation failed. Check device state over SSH."}})
    content_length = len(body) if isinstance(body, bytes) else os.fstat(body.fileno()).st_size
    output = [("Status", str(code)), ("Content-Type", content_type),
              ("Content-Length", str(content_length)),
              ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
              ("Referrer-Policy", "no-referrer"),
              ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "
               "img-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; "
               "base-uri 'none'; form-action 'self'")] + headers
    sys.stdout.buffer.write(("".join(k + ": " + v + "\r\n" for k, v in output) + "\r\n").encode())
    if isinstance(body, bytes):
        sys.stdout.buffer.write(body)
    else:
        with body:
            shutil.copyfileobj(body, sys.stdout.buffer, length=65536)


if __name__ == "__main__":
    main()
