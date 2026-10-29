import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[5]
OVERLAY = ROOT / "project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


web = load("webui", OVERLAY / "opt/vpn-web/webui.py")
archive = load("vpn_archive", OVERLAY / "opt/pivpn/archive.py")
prune = load("prune_backups", OVERLAY / "opt/pivpn/prune-backups.py")


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.auth, self.run = root / "auth", root / "run"
        self.wg, self.backups = root / "wg", root / "backups"
        for directory in (self.auth, self.run / "sessions", self.wg / "configs", self.backups):
            directory.mkdir(parents=True, mode=0o700)
        self.settings = root / "setupVars.conf"
        self.settings.write_text((OVERLAY / "etc/pivpn/wireguard/setupVars.conf").read_text())
        self.auth.joinpath("setup-token").write_text("a" * 64 + "\n")
        for name, value in (("AUTH", self.auth), ("RUN", self.run), ("WG", self.wg),
                            ("BACKUPS", self.backups), ("SETTINGS", self.settings)):
            patcher = patch.object(web, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.clock = patch.object(web, "uptime", return_value=1000.0).start()
        self.addCleanup(patch.stopall)
        self.password = "A unique test 42"
        self.cookie = ""

    def request(self, route, fields=None, method=None, environ=None):
        body = urlencode(fields).encode() if fields is not None else b""
        env = {"PATH_INFO": "/" + route, "REQUEST_METHOD": method or ("POST" if fields is not None else "GET"),
               "HTTP_HOST": "192.168.0.10:8080", "HTTP_ORIGIN": "http://192.168.0.10:8080",
               "HTTP_X_VPN_UI": "1", "HTTP_COOKIE": self.cookie, "QUERY_STRING": "",
               "CONTENT_TYPE": "application/x-www-form-urlencoded", "CONTENT_LENGTH": str(len(body))}
        env.update(environ or {})
        return web.dispatch(env, io.BytesIO(body))

    def provision(self):
        self.request("setup", {"token": "a" * 64, "password": self.password,
                               "password_confirm": self.password})

    def sign_in(self):
        result = self.request("login", {"password": self.password})
        self.cookie = dict(result[3])["Set-Cookie"].split(";")[0]
        return result

    def assert_error(self, status, callback):
        with self.assertRaises(web.APIError) as raised:
            callback()
        self.assertEqual(status, raised.exception.status)

    def test_setup_token_password_and_atomic_provision(self):
        self.assert_error(403, lambda: self.request("setup", {
            "token": "wrong", "password": self.password, "password_confirm": self.password}))
        self.assertFalse((self.auth / "auth.conf").exists())
        self.provision()
        verifier = json.loads((self.auth / "auth.conf").read_text())
        self.assertNotIn(self.password, str(verifier))
        self.assertEqual(0o600, (self.auth / "auth.conf").stat().st_mode & 0o777)
        self.assertFalse((self.auth / "setup-token").exists())
        self.assert_error(409, self.provision)

    def test_setup_password_length_and_character_requirements(self):
        for password in ("Short7A", "A" + "a" * 31 + "1", "lowercase1", "UPPERCASE1",
                         "Mixedcase"):
            self.clock.return_value += 60
            self.assert_error(400, lambda password=password: self.request("setup", {
                "token": "a" * 64, "password": password, "password_confirm": password}))
        for password in ("Abcdef1x", "A" + "a" * 30 + "1"):
            self.clock.return_value += 60
            self.request("setup", {"token": "a" * 64, "password": password,
                                   "password_confirm": password})
            (self.auth / "auth.conf").unlink()
            (self.auth / "setup-token").write_text("a" * 64 + "\n")
        self.clock.return_value += 60
        self.assert_error(400, lambda: self.request("setup", {
            "token": "a" * 64, "password": "Abcdef1x", "password_confirm": "Abcdef1y"}))

    def test_setup_persistence_failure_preserves_token(self):
        with patch.object(web, "atomic", side_effect=[None, OSError("disk full")]):
            with self.assertRaises(OSError):
                self.provision()
        self.assertTrue((self.auth / "setup-token").exists())
        self.assertFalse((self.auth / "auth.conf").exists())

    def test_login_cookie_and_fixed_expiry(self):
        self.provision()
        result = self.sign_in()
        cookie = dict(result[3])["Set-Cookie"]
        for value in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(value, cookie)
        self.assertNotIn("Domain=", cookie)
        self.assertNotIn("Max-Age=", cookie)
        env = {"HTTP_COOKIE": self.cookie}
        self.assertTrue(web.authenticated(env))
        self.clock.return_value += 1799
        self.assertTrue(web.authenticated(env))
        self.clock.return_value += 1
        self.assertFalse(web.authenticated(env))
        self.assertEqual([], list((self.run / "sessions").iterdir()))

    def test_logout_revokes_only_current_session_and_is_idempotent(self):
        self.provision()
        self.sign_in()
        first = self.cookie
        self.sign_in()
        second = self.cookie
        self.cookie = first
        result = self.request("logout", {})
        self.assertIn("Max-Age=0", dict(result[3])["Set-Cookie"])
        self.assertFalse(web.authenticated({"HTTP_COOKIE": first}))
        self.assertTrue(web.authenticated({"HTTP_COOKIE": second}))
        self.request("logout", {})
        self.cookie = ""
        self.request("logout", {})

    def test_logout_storage_error_not_success(self):
        self.provision()
        self.sign_in()
        with patch.object(Path, "unlink", side_effect=PermissionError("read-only")):
            with self.assertRaises(PermissionError):
                self.request("logout", {})

    def test_cross_origin_and_wrong_method_rejected(self):
        self.assert_error(403, lambda: self.request("logout", {}, environ={"HTTP_ORIGIN": "https://evil.test"}))
        self.assert_error(403, lambda: self.request("logout", {}, environ={"HTTP_X_VPN_UI": ""}))
        self.assert_error(403, lambda: self.request("logout", {}, environ={"HTTP_HOST": "evil.test:8080"}))
        self.assert_error(405, lambda: self.request("logout"))

    def test_protected_routes_require_login_before_parsing_or_execution(self):
        page = self.request("app")
        self.assertEqual(302, page[0])
        self.assertEqual("/", dict(page[3])["Location"])
        for route in ("status", "clients", "backups", "client-config", "client-qr", "backup-download"):
            self.assert_error(401, lambda route=route: self.request(route))
        for route in ("client-add", "leds", "restore", "backup-create", "backup-delete", "backup-upload"):
            self.assert_error(401, lambda route=route: self.request(route, {}))

    def test_duplicate_invalid_and_double_encoded_fields_rejected(self):
        for data in ("password=a&password=b", "password=%GG", "unknown=a", "password=%00"):
            self.assert_error(400, lambda data=data: web.parse_fields(data, ("password",)))
        self.assertEqual({"password": "%41"}, web.parse_fields("password=%2541", ("password",)))

    def test_empty_form_without_cgi_length_is_valid_only_for_fieldless_routes(self):
        env = {"CONTENT_TYPE": "application/x-www-form-urlencoded"}
        self.assertEqual({}, web.form(env, io.BytesIO(), ()))
        self.assert_error(411, lambda: web.form(env, io.BytesIO(), ("password",)))

    def test_duplicate_cookie_does_not_authenticate(self):
        self.provision()
        self.sign_in()
        self.assertFalse(web.authenticated({"HTTP_COOKIE": self.cookie + "; " + self.cookie}))
        self.assertFalse(web.authenticated({"HTTP_COOKIE": "vpn_session=../../auth.conf"}))

    def test_rate_limit_and_session_bounds(self):
        for _ in range(5):
            web.rate_limit(1000)
        self.assert_error(429, lambda: web.rate_limit(1001))
        web.rate_limit(1061)
        self.provision()
        for index in range(8):
            (self.run / "sessions" / (f"{index:064x}")).write_text("1000")
        self.assert_error(429, self.sign_in)

    def test_reboot_uptime_invalidates_sessions(self):
        self.provision()
        self.sign_in()
        self.clock.return_value = 10
        self.assertFalse(web.authenticated({"HTTP_COOKIE": self.cookie}))

    def test_password_reprovisioning_invalidates_old_sessions(self):
        self.provision()
        self.sign_in()
        old = self.cookie
        (self.auth / "auth.conf").unlink()
        (self.auth / "setup-token").write_text("a" * 64 + "\n")
        self.assertFalse(web.authenticated({"HTTP_COOKIE": old}))
        self.provision()
        self.assertFalse(web.authenticated({"HTTP_COOKIE": old}))

    def test_command_failure_and_timeout_are_errors(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.communicate.return_value = (b"", None)
        process.returncode = 1
        with patch.object(web.subprocess, "Popen", return_value=process):
            self.assert_error(500, lambda: web.command(["false"]))
        process.pid = 12345
        process.communicate.side_effect = [subprocess.TimeoutExpired("test", 1), (b"", None)]
        with patch.object(web.subprocess, "Popen", return_value=process), patch.object(web.os, "killpg") as kill:
            self.assert_error(504, lambda: web.command(["test"]))
            kill.assert_called_once_with(12345, web.signal.SIGTERM)

    def test_down_interface_keeps_configured_clients_without_secrets(self):
        self.wg.joinpath("wg0.conf").write_text("### begin phone ###\nPrivateKey = secret\n### end phone ###\n")
        self.wg.joinpath("configs/clients.txt").write_text("phone public 100 10.6.0.2\n")
        with patch.object(web, "lock", return_value=contextlib.nullcontext()), patch.object(web, "wg_running", return_value=False):
            data = web.clients()
        self.assertEqual("phone", data["clients"][0]["name"])
        self.assertIsNone(data["clients"][0]["rx"])
        self.assertNotIn("secret", json.dumps(data))

    def test_led_partial_error_reports_resulting_state(self):
        with patch.object(web.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), patch.object(web, "led_state", return_value="mixed"):
            data, code = web.mutate("leds", {"enabled": "0"})
        self.assertEqual(500, code)
        self.assertEqual("mixed", data["leds"])
        self.assertFalse(data["ok"])
        self.assert_error(400, lambda: web.mutate("leds", {"enabled": "/sys/anything"}))

    def test_backup_path_constraints(self):
        self.assert_error(400, lambda: web.safe_backup("../secret"))
        path = self.backups / "pivpnbackup-20260101-000000.tgz"
        path.symlink_to(self.auth / "setup-token")
        self.assert_error(404, lambda: web.safe_backup(path.name))

    def test_backup_delete_requires_existing_safe_archive_and_removes_only_it(self):
        self.provision()
        self.sign_in()
        archive = self.backups / "pivpnbackup-20260101-000000.tgz"
        other = self.backups / "pivpnbackup-20260101-000001.tgz"
        archive.write_bytes(b"archive")
        other.write_bytes(b"keep")
        with patch.object(web, "lock", return_value=contextlib.nullcontext()):
            result = self.request("backup-delete", {"file": archive.name})
            self.assertEqual(200, result[0])
            self.assertFalse(archive.exists())
            self.assertEqual(b"keep", other.read_bytes())
            self.assert_error(400, lambda: self.request("backup-delete", {"file": "../secret"}))
            self.assert_error(404, lambda: self.request("backup-delete", {"file": archive.name}))
            link = self.backups / "pivpnbackup-20260101-000002.tgz"
            protected = self.auth / "protected"
            protected.write_bytes(b"keep")
            link.symlink_to(protected)
            self.assert_error(404, lambda: self.request("backup-delete", {"file": link.name}))
            self.assertEqual(b"keep", protected.read_bytes())

    def test_client_mutations_use_fixed_argv_and_report_saved_not_live(self):
        expected = {"client-add": ["add", "-n", "phone"],
                    "client-enable": ["on", "phone", "-y"],
                    "client-disable": ["off", "phone", "-y"],
                    "client-remove": ["remove", "phone", "-y"]}
        with patch.object(web, "command", return_value=b"") as command, patch.object(web, "wg_running", return_value=False):
            for operation, args in expected.items():
                data, code = web.mutate(operation, {"name": "phone"})
                command.assert_called_with(["/usr/sbin/pivpn"] + args, timeout=60)
                self.assertEqual(200, code)
                self.assertFalse(data["live"])
            self.assert_error(400, lambda: web.mutate("client-add", {"name": "$(id)"}))

    def test_profile_bytes_and_streamed_backup_download(self):
        self.provision()
        self.sign_in()
        profile = b"[Interface]\nPrivateKey = credential\n"
        (self.wg / "configs/phone.conf").write_bytes(profile)
        path = self.backups / "pivpnbackup-20260101-000000.tgz"
        path.write_bytes(b"archive bytes")
        with patch.object(web, "lock", return_value=contextlib.nullcontext()):
            result = self.request("client-config", environ={"QUERY_STRING": "name=phone"})
            self.assertEqual(profile, result[2])
            result = self.request("backup-download", environ={"QUERY_STRING": "file=" + path.name})
            self.assertFalse(isinstance(result[2], bytes))
            with result[2] as stream:
                self.assertEqual(path.read_bytes(), stream.read())

    def test_upload_limits_truncation_validation_and_cleanup(self):
        env = {"CONTENT_TYPE": "application/gzip", "CONTENT_LENGTH": str(web.UPLOAD_LIMIT + 1),
               "HTTP_X_VPN_BACKUP_NAME": "pivpnbackup-20261022-100716.tgz"}
        self.assert_error(413, lambda: web.upload(env, io.BytesIO()))
        env["CONTENT_LENGTH"] = "10"
        with patch.object(web, "lock", return_value=contextlib.nullcontext()):
            self.assert_error(400, lambda: web.upload(env, io.BytesIO(b"short")))
        self.assertEqual([], list(self.backups.iterdir()))
        env["CONTENT_LENGTH"] = "4"
        with patch.object(web, "lock", return_value=contextlib.nullcontext()), patch.object(web, "archive_module", return_value=archive):
            self.assert_error(400, lambda: web.upload(env, io.BytesIO(b"junk")))
        self.assertEqual([], list(self.backups.iterdir()))

    def test_upload_rejects_missing_or_invalid_filename_before_reading(self):
        stream = MagicMock()
        for name in ("", "../pivpnbackup-20261022-100716.tgz",
                     "/pivpnbackup-20261022-100716.tgz", "backup.tgz",
                     "pivpnbackup-20261022-100716.tgz\n", "pivpnbackup-20261022-100716-0.tgz"):
            with self.subTest(name=name):
                env = {"CONTENT_TYPE": "application/gzip", "CONTENT_LENGTH": "4",
                       "HTTP_X_VPN_BACKUP_NAME": name}
                self.assert_error(400, lambda: web.upload(env, stream))
        stream.read.assert_not_called()
        self.assertEqual([], list(self.backups.iterdir()))

    def test_upload_preserves_name_and_replaces_only_after_validation(self):
        target = self.backups / "pivpnbackup-20261022-100716-2.tgz"
        target.write_bytes(b"existing backup")
        os.utime(target, (1000, 1000))
        payload = b"validated replacement"
        env = {"CONTENT_TYPE": "application/gzip", "CONTENT_LENGTH": str(len(payload)),
               "HTTP_X_VPN_BACKUP_NAME": target.name}

        def validate(path):
            self.assertEqual(payload, path.read_bytes())
            self.assertEqual(b"existing backup", target.read_bytes())
            self.assertEqual(1000, target.stat().st_mtime)

        validator = types.SimpleNamespace(validate=validate)
        started = web.time.time()
        with patch.object(web, "lock", return_value=contextlib.nullcontext()), \
                patch.object(web, "archive_module", return_value=validator):
            result = web.upload(env, io.BytesIO(payload))
        self.assertEqual({"ok": True, "file": target.name}, result)
        self.assertEqual(payload, target.read_bytes())
        self.assertGreaterEqual(target.stat().st_mtime, started - 1)
        self.assertLessEqual(target.stat().st_mtime, web.time.time() + 1)
        self.assertEqual(0o600, target.stat().st_mode & 0o777)
        self.assertEqual([target], list(self.backups.iterdir()))
        self.assertEqual(target.stat().st_mtime, web.backup_list()[0]["modified"])

    def test_failed_upload_preserves_existing_backup(self):
        target = self.backups / "pivpnbackup-20261022-100716.tgz"
        target.write_bytes(b"existing backup")
        os.utime(target, (1000, 1000))
        env = {"CONTENT_TYPE": "application/gzip", "CONTENT_LENGTH": "4",
               "HTTP_X_VPN_BACKUP_NAME": target.name}
        validator = MagicMock()
        with patch.object(web, "lock", return_value=contextlib.nullcontext()), \
                patch.object(web, "archive_module", return_value=validator):
            self.assert_error(400, lambda: web.upload(env, io.BytesIO(b"x")))
            validator.validate.side_effect = ValueError("invalid archive")
            self.assert_error(400, lambda: web.upload(env, io.BytesIO(b"junk")))
            validator.validate.side_effect = None
            with patch.object(web.os, "replace", side_effect=OSError("write failed")):
                with self.assertRaises(OSError):
                    web.upload(env, io.BytesIO(b"data"))
        self.assertEqual(b"existing backup", target.read_bytes())
        self.assertEqual(1000, target.stat().st_mtime)
        self.assertEqual([target], list(self.backups.iterdir()))

    def test_pre_gui_backup_upload_download_and_restore(self):
        self.provision()
        self.sign_in()
        verifier = (self.auth / "auth.conf").read_bytes()
        key = base64.b64encode(b"x" * 32).decode()
        interface = "[Interface]\nPrivateKey = " + key + "\nAddress = 10.6.0.1/24\n"
        peer = "\n[Peer]\nPublicKey = " + key + "\nPresharedKey = " + key + "\nAllowedIPs = 10.6.0.2/32\n"
        files = {
            "userdata/wireguard/wg0.conf": interface + peer,
            "userdata/wireguard/server_priv": key + "\n",
            "userdata/wireguard/server_pub": key + "\n",
            "userdata/wireguard/configs/clients.txt": "my_phone " + key + " 1792656436 10.6.0.2\n",
            "userdata/wireguard/configs/my_phone.conf":
                "[Interface]\nPrivateKey = " + key + "\nAddress = 10.6.0.2/24\n"
                "DNS = 9.9.9.9, 149.112.112.112\nMTU = 1420\n\n[Peer]\nPublicKey = " + key +
                "\nPresharedKey = " + key + "\nAllowedIPs = 0.0.0.0/0, ::/0\n"
                "Endpoint = vpn.example.test:51820\nPersistentKeepalive = 25\n",
            "etc/pivpn/wireguard/setupVars.conf": self.settings.read_text()}
        for suffix in ("priv", "pub", "psk"):
            files["userdata/wireguard/keys/my_phone_" + suffix] = key + "\n"
        directories = ("userdata/wireguard", "userdata/wireguard/keys",
                       "userdata/wireguard/configs", "etc/pivpn", "etc/pivpn/wireguard")
        for kind in (tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT):
            with self.subTest(format=kind):
                source = io.BytesIO()
                with tarfile.open(fileobj=source, mode="w:gz", format=kind) as target:
                    for name in directories:
                        member = tarfile.TarInfo(name)
                        member.type = tarfile.DIRTYPE
                        target.addfile(member)
                    for name, value in files.items():
                        data = value.encode()
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        target.addfile(member, io.BytesIO(data))
                payload = source.getvalue()
                env = {"PATH_INFO": "/backup-upload", "REQUEST_METHOD": "POST",
                       "HTTP_HOST": "192.168.0.10:8080", "HTTP_ORIGIN": "http://192.168.0.10:8080",
                       "HTTP_X_VPN_UI": "1", "HTTP_COOKIE": self.cookie, "QUERY_STRING": "",
                       "HTTP_X_VPN_BACKUP_NAME": "pivpnbackup-20261022-100716.tgz",
                       "CONTENT_TYPE": "application/gzip", "CONTENT_LENGTH": str(len(payload))}
                with patch.object(web, "lock", return_value=contextlib.nullcontext()), \
                        patch.object(web, "archive_module", return_value=archive), \
                        patch.object(web, "command", return_value=b"") as command:
                    uploaded = web.dispatch(env, io.BytesIO(payload))
                    self.assertEqual(200, uploaded[0])
                    result = json.loads(uploaded[2])
                    self.assertTrue(result["ok"])
                    name = result["file"]
                    self.assertEqual(env["HTTP_X_VPN_BACKUP_NAME"], name)
                    listed = json.loads(self.request("backups")[2])["backups"]
                    self.assertIn(name, [row["file"] for row in listed])
                    download = self.request("backup-download", environ={"QUERY_STRING": "file=" + name})
                    with download[2] as stream:
                        self.assertEqual(payload, stream.read())
                    destination = Path(self.temp.name) / ("restore-" + str(kind))
                    destination.mkdir(mode=0o700)
                    archive.validate(self.backups / name, destination)
                    for filename, value in files.items():
                        extracted = destination / filename
                        self.assertEqual(value.encode(), extracted.read_bytes())
                        self.assertEqual(0o600, extracted.stat().st_mode & 0o777)
                    restored = self.request("restore", {"file": name})
                    self.assertEqual(200, restored[0])
                    self.assertTrue(json.loads(restored[2])["ok"])
                    command.assert_called_once_with(
                        ["/usr/sbin/pivpn", "restore", str(self.backups / name), "-y"], timeout=120)
                    self.assertEqual(verifier, (self.auth / "auth.conf").read_bytes())

    def test_exact_upload_limit_is_streamed_in_bounded_chunks(self):
        class Chunks:
            remaining = web.UPLOAD_LIMIT
            largest = 0

            def read(self, size):
                self.largest = max(size, self.largest)
                count = min(self.remaining, size)
                self.remaining -= count
                return b"x" * count
        stream = Chunks()
        env = {"CONTENT_TYPE": "application/gzip", "CONTENT_LENGTH": str(web.UPLOAD_LIMIT),
               "HTTP_X_VPN_BACKUP_NAME": "pivpnbackup-20261022-100716.tgz"}
        validated = []
        validator = types.SimpleNamespace(validate=lambda path: validated.append(path.stat().st_size))
        with patch.object(web, "lock", return_value=contextlib.nullcontext()), patch.object(web, "archive_module", return_value=validator):
            result = web.upload(env, stream)
        self.assertTrue(result["ok"])
        self.assertEqual([web.UPLOAD_LIMIT], validated)
        self.assertLessEqual(stream.largest, 65536)
        self.assertEqual(web.UPLOAD_LIMIT, (self.backups / result["file"]).stat().st_size)

    def test_metrics_actual_host_shape(self):
        usage = web.shutil.disk_usage("/")
        with patch.object(web.shutil, "disk_usage", return_value=usage):
            data = web.metrics()
        self.assertGreater(data["cpu"]["total"], 0)
        self.assertGreater(data["memory"]["total"], 0)
        self.assertEqual({"eth0", "wg0"}, set(data["networks"]))

    def test_public_state_accepts_no_query_fields(self):
        data = json.loads(self.request("state")[2])
        self.assertTrue(data["setup"])
        self.provision()
        self.assertFalse(json.loads(self.request("state")[2])["setup"])


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        key = base64.b64encode(b"x" * 32).decode()
        self.files = {
            "userdata/wireguard/wg0.conf": "[Interface]\nPrivateKey = " + key + "\nAddress = 10.6.0.1/24\n",
            "userdata/wireguard/server_priv": key + "\n",
            "userdata/wireguard/server_pub": key + "\n",
            "userdata/wireguard/configs/clients.txt": "",
            "etc/pivpn/wireguard/setupVars.conf": (OVERLAY / "etc/pivpn/wireguard/setupVars.conf").read_text()}

    def make_archive(self, extra=None):
        path = self.root / "backup.tgz"
        with tarfile.open(path, "w:gz") as target:
            for name, text in self.files.items():
                data = text.encode()
                member = tarfile.TarInfo(name)
                member.size = len(data)
                target.addfile(member, io.BytesIO(data))
            if extra is not None:
                target.addfile(extra)
        return path

    def test_valid_archive_and_private_extraction(self):
        path = self.make_archive()
        archive.validate(path)
        dest = self.root / "extracted"
        dest.mkdir(mode=0o700)
        archive.validate(path, dest)
        for name, text in self.files.items():
            self.assertEqual(text, (dest / name).read_text())
            self.assertEqual(0o600, (dest / name).stat().st_mode & 0o777)

    def test_symlinks_hardlinks_traversal_and_duplicates_rejected(self):
        for name, kind in (("userdata/wireguard/keys/link", tarfile.SYMTYPE),
                           ("userdata/wireguard/keys/link", tarfile.LNKTYPE),
                           ("userdata/wireguard/../../outside", tarfile.REGTYPE),
                           ("/userdata/wireguard/wg0.conf", tarfile.REGTYPE),
                           ("userdata/wireguard/wg0.conf", tarfile.REGTYPE),
                           ("PaxHeaders/payload", tarfile.XHDTYPE),
                           ("././@LongLink", tarfile.GNUTYPE_LONGNAME)):
            extra = tarfile.TarInfo(name)
            extra.type = kind
            extra.linkname = "/etc/passwd"
            with self.assertRaises(ValueError):
                archive.validate(self.make_archive(extra))

    def test_configuration_commands_and_disabled_hooks_rejected(self):
        for directive in ("PostUp = touch /tmp/unsafe", "#[disabled] PostUp = touch /tmp/unsafe"):
            self.files["userdata/wireguard/wg0.conf"] += "\n" + directive
            with self.assertRaises(ValueError):
                archive.validate(self.make_archive())

    def test_shell_commands_in_restored_settings_rejected(self):
        self.files["etc/pivpn/wireguard/setupVars.conf"] += '\npivpnHOST="$(id)"\n'
        with self.assertRaises(ValueError):
            archive.validate(self.make_archive())

    def test_missing_required_file_and_corrupt_gzip_rejected(self):
        del self.files["userdata/wireguard/server_priv"]
        with self.assertRaises(ValueError):
            archive.validate(self.make_archive())
        path = self.make_archive()
        path.write_bytes(path.read_bytes()[:-6])
        with self.assertRaises(ValueError):
            archive.validate(path)

    def test_expanded_size_limit(self):
        path = self.make_archive()
        with patch.object(archive, "MAX_EXPANDED", 100):
            with self.assertRaises(ValueError):
                archive.validate(path)

    def test_retention_uses_mtime_and_keeps_current_when_clock_moves_back(self):
        current = None
        for index in range(12):
            current = self.root / ("pivpnbackup-20260101-000000-" + str(index + 1) + ".tgz")
            current.write_bytes(b"backup")
            os.utime(current, (100 + index, 100 + index))
        os.utime(current, (1, 1))
        prune.prune(self.root, 5, current)
        self.assertEqual(5, len(list(self.root.glob("*.tgz"))))
        self.assertTrue(current.exists())

    def test_retention_orders_numeric_suffixes_when_mtimes_tie(self):
        paths = []
        for index in range(1, 13):
            path = self.root / ("pivpnbackup-20260101-000000-" + str(index) + ".tgz")
            path.write_bytes(b"backup")
            os.utime(path, (100, 100))
            paths.append(path)
        prune.prune(self.root, 5, paths[-1])
        self.assertEqual(set(paths[-5:]), set(self.root.glob("*.tgz")))


class BackupCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backups = self.root / "backups"
        binary = self.root / "bin"
        binary.mkdir()
        self.env = dict(os.environ, PATH=str(binary) + ":/usr/bin:/bin")
        for name, script in {
            "date": "#!/bin/sh\nprintf '20260101-000000\\n'\n",
            "tar": "#!/bin/sh\nprintf 'archive payload\\n'\nexit ${TAR_FAIL:-0}\n",
        }.items():
            path = binary / name
            path.write_text(script)
            path.chmod(0o755)
        common = self.root / "common.sh"
        common.write_text(f"""WGDIR={self.root}
BACKUP_DIR={self.backups}
die() {{ echo "$*" >&2; exit 1; }}
take_lock() {{ exec 9>{self.root}/vpn.lock; flock -n 9 || exit 1; }}
require_server() {{ :; }}
""")
        self.script = self.root / "backup.sh"
        self.script.write_text((OVERLAY / "opt/pivpn/backup.sh").read_text().replace(
            "/opt/pivpn/common.sh", str(common)).replace(
            "/opt/pivpn/prune-backups.py", str(OVERLAY / "opt/pivpn/prune-backups.py")))

    def test_same_second_backups_never_overwrite_and_retain_five(self):
        for _ in range(12):
            before = {p.name for p in self.backups.glob("*.tgz")}
            result = subprocess.run(["bash", str(self.script), "--web"],
                                    env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)
            created = result.stdout.decode().strip()
            self.assertNotIn(created, before)
            self.assertTrue((self.backups / created).is_file())
            self.assertLessEqual(len(list(self.backups.glob("*.tgz"))), 5)
        self.assertEqual(5, len(list(self.backups.glob("*.tgz"))))

    def test_failed_tar_is_not_published_even_if_gzip_succeeds(self):
        result = subprocess.run(["bash", str(self.script), "--web"],
                                env=dict(self.env, TAR_FAIL="1"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list(self.backups.iterdir()))


if __name__ == "__main__":
    unittest.main()
