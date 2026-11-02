"""Native/Python contracts in isolated storage; no writes to host VPN state."""

import base64
import concurrent.futures
import contextlib
import fcntl
import http.client
import io
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from test_vpn_web import OVERLAY, ROOT, web

SOURCE = ROOT / "sysdrv/tools/board/buildroot/packages/vpn-web/src"
SID = "a" * 64
KEY = base64.b64encode(b"x" * 32).decode()


def build(binary, root, snapshot=None, frozen_clock=True):
    compiler = os.environ.get("VPN_TEST_CC", "gcc")
    flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-Wformat=2", "-Wshadow", "-Wconversion",
             "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-D_LARGEFILE64_SOURCE"]
    if os.environ.get("VPN_TEST_SANITIZERS") == "1":
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-no-pie"]
    command = [compiler, *flags, f'-DVPN_ROOT="{root}"',
               f"-DVPN_OWNER_UID={os.geteuid()}",
               f'-DVPN_PYTHON_SCRIPT="{Path(root or "/") / "bootstrap.py"}"',
               "-I", str(SOURCE), str(SOURCE / "web.c"), str(SOURCE / "metrics.c"),
               str(snapshot or SOURCE / "netlink.c"), "-ljson-c", "-lm", "-o", str(binary)]
    if frozen_clock:
        command.insert(1, "-DVPN_TEST_CLOCK=1000000.25")
    subprocess.run(command, check=True, stdout=subprocess.PIPE)


class NativeFixture:
    def fixture(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-native-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth = self.root / "userdata/webui"
        self.run = self.root / "run/webui"
        self.wg = self.root / "userdata/wireguard"
        self.backups = self.root / "userdata/vpn-backup"
        self.settings = self.root / "etc/pivpn/wireguard/setupVars.conf"
        for directory in (self.auth, self.run, self.run / "sessions", self.wg / "configs",
                          self.settings.parent, self.root / "proc", self.backups):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        self.private(self.auth / "auth.conf", json.dumps({
            "algorithm": "pbkdf2-sha256", "iterations": web.ITERATIONS,
            "salt": "b" * 64, "hash": "c" * 64}))
        self.private(self.run / "sessions" / SID, "1000.25")
        self.private(self.run / "auth.lock", "")
        self.private(self.root / "run/pivpn.lock", "")
        self.settings.write_text((OVERLAY / "etc/pivpn/wireguard/setupVars.conf").read_text())
        (self.wg / "wg0.conf").write_text("[Interface]\nPrivateKey = never-serialize\n")
        (self.wg / "configs/clients.txt").write_text("")
        (self.root / "proc/uptime").write_text("1000.25 100.0\n")
        (self.root / "proc/stat").write_text("cpu 1 2 3 4 5 6 7 8 999 999\n")
        (self.root / "proc/meminfo").write_text(
            "MemTotal: 65536 kB\nMemAvailable: 35000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
        for name in ("eth0", "wg0"):
            statistics = self.root / f"sys/class/net/{name}/statistics"
            statistics.mkdir(parents=True)
            (statistics / "rx_bytes").write_text(str(2**63 + 7))
            (statistics / "tx_bytes").write_text(str(2**64 - 1))
        bootstrap = f"""import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('web', {str(OVERLAY / 'opt/vpn-web/webui.py')!r})
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)
web.AUTH = Path({str(self.auth)!r})
web.RUN = Path({str(self.run)!r})
web.WG = Path({str(self.wg)!r})
web.BACKUPS = Path({str(self.backups)!r})
sys.path.insert(0, {str(OVERLAY / 'opt/pivpn')!r})
web.STORAGE_UID = {os.geteuid()}
original_lock = web.lock
web.lock = lambda path, shared=False: original_lock(
    Path({str(self.root / 'run/pivpn.lock')!r}) if str(path) == '/run/pivpn.lock' else path, shared)
web.main()
"""
        (self.root / "bootstrap.py").write_text(bootstrap)
        self.binary = self.root / "vpn-native"
        build(self.binary, self.root)
        self.cookie = "vpn_session=" + SID

    @staticmethod
    def private(path, value):
        path.write_text(value)
        path.chmod(0o600)

    def native(self, route="clients", cookie=None, method="GET", query="", binary=None):
        env = dict(os.environ, PATH_INFO="/" + route, REQUEST_METHOD=method,
                   QUERY_STRING=query, HTTP_COOKIE=self.cookie if cookie is None else cookie)
        result = subprocess.run([str(binary or self.binary)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        head, raw = result.stdout.split(b"\r\n\r\n", 1)
        headers = dict(line.decode().split(": ", 1) for line in head.split(b"\r\n"))
        self.assertEqual(len(raw), int(headers["Content-Length"]))
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertEqual("nosniff", headers["X-Content-Type-Options"])
        self.assertEqual("no-referrer", headers["Referrer-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        return int(headers["Status"]), headers, json.loads(raw)

    @contextlib.contextmanager
    def python_state(self):
        with contextlib.ExitStack() as stack:
            for name, value in (("AUTH", self.auth), ("RUN", self.run), ("WG", self.wg),
                                ("BACKUPS", self.backups), ("STORAGE_UID", os.geteuid())):
                stack.enter_context(patch.object(web, name, value))
            stack.enter_context(patch.object(web, "uptime", return_value=1000.25))
            original_lock = web.lock
            stack.enter_context(patch.object(web, "lock", side_effect=lambda path, shared=False:
                original_lock(self.root / "run/pivpn.lock" if str(path) == "/run/pivpn.lock" else path, shared)))
            yield

    def python(self, route="backups", cookie=None, query=""):
        env = {"PATH_INFO": "/" + route, "REQUEST_METHOD": "GET",
               "HTTP_COOKIE": self.cookie if cookie is None else cookie, "QUERY_STRING": query}
        with self.python_state():
            try:
                result = web.dispatch(env, io.BytesIO())
                return result[0], json.loads(result[2])
            except web.APIError as error:
                return error.status, {"ok": False, "error": {"code": error.code, "message": error.message}}
            except (OSError, ValueError, KeyError, RuntimeError):
                return 500, {"ok": False, "error": {
                    "code": "internal", "message": "Device operation failed. Check device state over SSH."}}


class NativeTests(NativeFixture, unittest.TestCase):
    def setUp(self):
        if any(name == "wg0" for _, name in socket.if_nameindex()):
            self.skipTest("host wg0 exists; use an isolated network namespace")
        self.fixture()

    def test_down_clients_zero_through_nine_and_no_secrets(self):
        for count in range(10):
            config, metadata = [], []
            for i in range(count):
                name = f"phone{i}"
                prefix = "#[disabled] " if i % 2 else ""
                config.append(prefix + f"### begin {name} ###\nPrivateKey = never-serialize\n")
                metadata.append(f"{name} {KEY} {2**53 + i} 10.6.0.{i + 2}\n")
            (self.wg / "wg0.conf").write_text("".join(config))
            (self.wg / "configs/clients.txt").write_text("".join(metadata))
            code, _, data = self.native()
            self.assertEqual(200, code)
            self.assertEqual({"ok": True, "running": False,
                              "timestamps": "approximate until NTP sync",
                              "clients": [{"name": f"phone{i}", "ip": f"10.6.0.{i + 2}",
                                           "created": 2**53 + i, "enabled": not i % 2,
                                           "handshake": None, "recent": False, "endpoint": None,
                                           "rx": None, "tx": None} for i in range(count)]}, data)
            self.assertNotIn("never-serialize", json.dumps(data))

    def test_maximum_metadata_fixture_and_explicit_input_limits(self):
        for count, expected in ((1024, 200), (1025, 500)):
            (self.wg / "wg0.conf").write_text("".join(
                f"### begin phone{i} ###\n" for i in range(count)))
            (self.wg / "configs/clients.txt").write_text("".join(
                f"phone{i} {KEY} 123 10.6.0.2\n" for i in range(count)))
            code, _, data = self.native()
            self.assertEqual(expected, code, data if code != 200 else None)
            if code == 200:
                self.assertEqual(count, len(data["clients"]))
        (self.wg / "configs/clients.txt").write_text("x" * (128 * 1024 + 1))
        self.assertEqual(500, self.native()[0])

    def test_slow_response_consumer_is_bounded_and_does_not_hold_vpn_lock(self):
        count = 256
        (self.wg / "wg0.conf").write_text("".join(
            f"### begin phone{i} ###\n" for i in range(count)))
        (self.wg / "configs/clients.txt").write_text("".join(
            f"phone{i} {KEY} 123 10.6.0.2\n" for i in range(count)))
        read_fd, write_fd = os.pipe()
        fcntl.fcntl(read_fd, fcntl.F_SETPIPE_SZ, 4096)
        process = None
        try:
            process = subprocess.Popen([str(self.binary)], stdout=write_fd, stderr=subprocess.PIPE,
                env=dict(os.environ, PATH_INFO="/clients", REQUEST_METHOD="GET",
                         QUERY_STRING="", HTTP_COOKIE=self.cookie))
            os.close(write_fd)
            write_fd = -1
            self.assertEqual([read_fd], select.select([read_fd], [], [], 2)[0])
            self.assertIsNone(process.poll())
            with (self.root / "run/pivpn.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(1, process.wait(timeout=7))
            self.assertIn(b"response write failed (timeout)", process.stderr.read())
            with os.fdopen(read_fd, "rb") as handle:
                read_fd = -1
                partial = handle.read()
            with self.assertRaises(json.JSONDecodeError):
                json.loads(partial.split(b"\r\n\r\n", 1)[1])
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                process.stderr.close()
            if read_fd >= 0:
                os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_status_schema_counters_nullable_metrics_and_leds(self):
        code, _, data = self.native("status")
        self.assertEqual(200, code, data)
        self.assertFalse(data["running"])
        self.assertIsNone(data["address"])
        self.assertEqual(51820, data["listen_port"])
        metrics = data["metrics"]
        self.assertEqual({"total": 36, "idle": 9}, metrics["cpu"])
        self.assertEqual(35000 * 1024, metrics["memory"]["available"])
        self.assertEqual({"rx": 2**63 + 7, "tx": 2**64 - 1}, metrics["networks"]["eth0"])
        self.assertEqual(1000.25, metrics["uptime"])
        self.assertEqual([0.1, 0.2, 0.3], metrics["load"])
        self.assertEqual("unavailable", data["leds"])
        for entry in metrics["storage"]:
            usage = shutil.disk_usage(self.root / entry["path"].lstrip("/"))
            self.assertEqual((usage.total, usage.used, usage.free),
                             (entry["total"], entry["used"], entry["free"]))
        meminfo = self.root / "proc/meminfo"
        meminfo.write_text(meminfo.read_text().replace("MemAvailable: 35000 kB\n", ""))
        self.assertIsNone(self.native("status")[2]["metrics"]["memory"]["available"])
        thermal = self.root / "sys/class/thermal/thermal_zone0"
        thermal.mkdir(parents=True)
        (thermal / "type").write_text("cpu-thermal\n")
        (thermal / "temp").write_text("42500\n")
        self.assertEqual([{"name": "cpu-thermal", "celsius": 42.5}],
                         self.native("status")[2]["metrics"]["temperatures"])
        (thermal / "temp").write_text("broken\n")
        self.assertEqual([{"name": "thermal_zone0", "celsius": None}],
                         self.native("status")[2]["metrics"]["temperatures"])

    def test_thermal_ordering_and_led_semantics(self):
        for zone, name, temp in (("thermal_zone2", "cpu", "42625"),
                                 ("thermal_zone10", "optional", "invalid")):
            directory = self.root / "sys/class/thermal" / zone
            directory.mkdir(parents=True)
            (directory / "type").write_text(name)
            (directory / "temp").write_text(temp)
        for name in ("eth_link", "eth_act", "work"):
            directory = self.root / "sys/class/leds" / name
            directory.mkdir(parents=True)
            (directory / "trigger").write_text("[activity]" if name == "work" else "[netdev]")
            (directory / "device_name").write_text("eth0")
            for field, value in {"link": "1" if name == "eth_link" else "0",
                                 "rx": "0" if name == "eth_link" else "1",
                                 "tx": "0" if name == "eth_link" else "1"}.items():
                (directory / field).write_text(value)
        def mapped_path(path):
            path = str(path)
            return self.root / path.lstrip("/") if path.startswith(("/proc/", "/sys/")) else Path(path)

        with self.python_state(), patch.object(web, "Path", side_effect=mapped_path), \
                patch.object(web.os, "getloadavg", return_value=(0.1, 0.2, 0.3)):
            data = self.native("status")[2]
            self.assertEqual([{"name": "thermal_zone10", "celsius": None},
                              {"name": "cpu", "celsius": 42.625}],
                             data["metrics"]["temperatures"])
            self.assertEqual("enabled", data["leds"])
            self.assertEqual(web.led_state(), data["leds"])
            for name in ("eth_link", "eth_act", "work"):
                directory = self.root / "sys/class/leds" / name
                (directory / "trigger").write_text("[none]")
                (directory / "brightness").write_text("0")
            self.assertEqual("disabled", self.native("status")[2]["leds"])
            self.assertEqual("disabled", web.led_state())
            (self.root / "sys/class/leds/work/trigger").write_text("[activity]")
            self.assertEqual("mixed", self.native("status")[2]["leds"])
            self.assertEqual("mixed", web.led_state())
            (self.root / "sys/class/leds/work/trigger").unlink()
            self.assertEqual("unavailable", self.native("status")[2]["leds"])
            self.assertEqual("unavailable", web.led_state())

    def test_cookie_error_parity_and_authorization_precedence(self):
        for cookie in ("", "vpn_session=../bad", "vpn_session=" + "A" * 64,
                       "vpn_session=" + SID + "; vpn_session=" + SID,
                       "vpn_session=" + SID + "0", "other=x",
                       "other=" + "x" * 8192 + "; " + self.cookie):
            expected = self.python(cookie=cookie, query="%broken")
            code, _, data = self.native(cookie=cookie, query="%broken")
            self.assertEqual(expected, (code, data))
        for cookie in (self.cookie, "other=x; " + self.cookie, "  " + self.cookie + "  "):
            self.assertEqual(200, self.native(cookie=cookie)[0])
        for query in ("%bad", "x=1", "missing", "x" * 4097, "x=1&missing",
                      "&", "x=1&", "x=%ff", "x=%c0%80", "x=%e2%82%ac",
                      "&x=1", "x=1&&y=2", "x=1&y=%ff", "&".join(["x=1"] * 9)):
            expected = self.python(query=query)
            code, _, data = self.native(query=query)
            self.assertEqual(expected, (code, data))

    def test_exact_fixed_expiry_fractional_reboot_and_corrupt_timestamps(self):
        session = self.run / "sessions" / SID
        for issued, expected in (("1000.25", 200), ("1000.26", 401), ("0", 200),
                                 ("nan", 500), ("inf", 500), ("-1", 500),
                                 ("1_000", 500), ("0x1p1", 500), ("1000 garbage", 500),
                                 ("1000.2500\n", 200), ("1e-9999", 200), ("\v1000.25\f", 200)):
            self.private(session, issued)
            python = self.python()
            code, _, data = self.native()
            self.assertEqual(expected, code, (issued, data))
            self.assertEqual(expected, python[0])
            if expected != 200:
                self.assertEqual(python, (code, data))
        self.private(session, "1000.25")
        (self.root / "proc/uptime").write_text("2800.25 100\n")
        self.assertEqual(401, self.native()[0])
        self.assertTrue(session.exists())
        (self.root / "proc/uptime").write_text("2800.24 100\n")
        self.assertEqual(200, self.native()[0])
        (self.root / "proc/uptime").write_text("1.0 0\n")
        self.assertEqual(401, self.native()[0])

    def test_private_storage_failures_and_missing_account(self):
        session = self.run / "sessions" / SID
        session.chmod(0o644)
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])
        session.chmod(0o600)
        session.unlink()
        session.symlink_to(self.auth / "auth.conf")
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])
        session.unlink()
        self.assertEqual(401, self.native()[0])
        self.private(session, "1000.25")
        account = self.auth / "auth.conf"
        original = account.read_text()
        account.unlink()
        self.assertEqual(401, self.native()[0])
        self.private(account, "{}")
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])
        verifier = json.loads(original)
        verifier["algorithm"] += "\0ignored"
        self.private(account, json.dumps(verifier))
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])
        verifier = json.loads(original)
        verifier["hash"] += "\0ignored"
        self.private(account, json.dumps(verifier))
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])
        self.private(account, original)
        self.run.chmod(0o755)
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])
        self.run.chmod(0o700)
        lock = self.run / "auth.lock"
        lock.unlink()
        lock.symlink_to(account)
        self.assertEqual(500, self.native()[0])
        lock.unlink()
        os.mkfifo(lock, 0o600)
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])
        lock.unlink()
        self.private(lock, "")
        session.unlink()
        os.mkfifo(session, 0o600)
        self.assertEqual(500, self.native()[0])
        self.assertEqual(500, self.python()[0])

    def test_shared_readers_bypass_gate_and_conflict_with_writers(self):
        self.private(self.run / "request.lock", "")
        with (self.run / "request.lock").open("a") as gate, \
                (self.run / "auth.lock").open("a") as auth, \
                (self.root / "run/pivpn.lock").open("a") as vpn:
            fcntl.flock(gate, fcntl.LOCK_EX)
            fcntl.flock(auth, fcntl.LOCK_SH)
            fcntl.flock(vpn, fcntl.LOCK_SH)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda route: self.native(route)[0], ("status", "clients")))
            self.assertEqual([200, 200], results)
            self.assertEqual(503, self.native("state")[0])
            fcntl.flock(auth, fcntl.LOCK_EX)
            self.assertEqual(409, self.native()[0])
            fcntl.flock(auth, fcntl.LOCK_UN)
            fcntl.flock(vpn, fcntl.LOCK_EX)
            self.assertEqual(409, self.native()[0])
        self.assertEqual(200, self.native()[0])
        with self.python_state():
            web.login("logout", {}, {"HTTP_COOKIE": self.cookie})
        self.assertEqual(401, self.native()[0])

    def test_settings_shlex_parity_and_malformed_inputs_fail(self):
        for assignment in ('ALLOWED_IPS="0.0.0.0/0, ::/0" # comment',
                           "ALLOWED_IPS='escaped \"quote\" and \\\\slash'",
                           'ALLOWED_IPS="a\\$b\\`c\\qd"',
                           "ALLOWED_IPS=one\\ word",
                           'ALLOWED_IPS=one" two"\' three\'',
                           'ALLOWED_IPS="one\ttwo"',
                           'ALLOWED_IPS="quoted \u00e9"'):
            self.settings.write_text("pivpnPORT=51820\n" + assignment + "\n")
            import shlex
            expected = shlex.split(assignment, comments=True)[0].split("=", 1)[1]
            data = self.native("status")[2]
            self.assertEqual(expected, data["settings"]["ALLOWED_IPS"])
        self.settings.write_text("pivpnPORT=invalid\npivpnPORT=51820\n")
        self.assertEqual(51820, self.native("status")[2]["listen_port"])
        for text in ('pivpnPORT=51820\nX="unterminated\n', "pivpnPORT=51820\nx=y z\n",
                     "pivpnPORT=51820\nbad\n", "pivpnPORT=999999\n"):
            self.settings.write_text(text)
            self.assertEqual(500, self.native("status")[0])
        self.settings.write_bytes(b"pivpnPORT=51820\nx=\0hidden")
        self.assertEqual(500, self.native("status")[0])
        (self.wg / "configs/clients.txt").write_text("bad metadata\n")
        self.assertEqual(500, self.native()[0])
        (self.wg / "wg0.conf").write_text("### begin phone ###\n")
        for row in (f"phone {KEY} 100 999.1.1.1\n", "phone bad-key 100 10.6.0.2\n",
                    f"phone {KEY} {2**64} 10.6.0.2\n", f"\nphone {KEY} 100 10.6.0.2\n"):
            (self.wg / "configs/clients.txt").write_text(row)
            self.assertEqual(500, self.native()[0])

    def test_route_normalization_method_and_unknown_route_cold_contract(self):
        self.assertEqual(200, self.native("/clients//")[0])
        self.private(self.run / "request.lock", "")
        with (self.run / "request.lock").open("a") as gate:
            fcntl.flock(gate, fcntl.LOCK_EX)
            for route in ("status", "clients"):
                for method in ("POST", "HEAD", ""):
                    self.assertEqual(405, self.native(route, method=method)[0])
        self.assertEqual(404, self.native("unknown")[0])
        self.assertEqual(404, self.native("clients/unknown")[0])
        self.assertEqual(200, self.native("state", cookie="")[0])

    def test_missing_configuration_and_partial_required_metrics(self):
        config = self.wg / "wg0.conf"
        config.unlink()
        self.assertEqual(503, self.native("status")[0])
        config.mkdir()
        self.assertEqual(503, self.native("status")[0])
        config.rmdir()
        config.write_text("[Interface]\n")
        tx = self.root / "sys/class/net/eth0/statistics/tx_bytes"
        tx.unlink()
        self.assertEqual(500, self.native("status")[0])
        tx.write_text(str(2**64))
        self.assertEqual(500, self.native("status")[0])

    def test_native_hot_paths_do_not_execute_helpers(self):
        tracer = shutil.which("strace")
        if tracer is None:
            self.skipTest("strace is not available")
        for route in ("status", "clients"):
            result = subprocess.run([tracer, "-f", "-e", "trace=execve", str(self.binary)],
                                    env=dict(os.environ, PATH_INFO="/" + route, REQUEST_METHOD="GET",
                                             QUERY_STRING="", HTTP_COOKIE=self.cookie,
                                             ASAN_OPTIONS="detect_leaks=0"),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True)
            self.assertEqual(1, result.stderr.count(b"execve("), result.stderr)

    def test_collection_deadline_returns_error_and_releases_locks(self):
        snapshot = self.root / "slow.c"
        snapshot.write_text("""#include "netlink.h"
#include <unistd.h>
int vpn_collect(struct vpn_device *d) { (void)d; sleep(10); return 0; }
""")
        binary = self.root / "slow-native"
        build(binary, self.root, snapshot)
        started = time.monotonic()
        code, _, data = self.native(binary=binary)
        self.assertEqual(504, code, data)
        self.assertEqual("timeout", data["error"]["code"])
        self.assertLess(time.monotonic() - started, 7)
        with (self.root / "run/pivpn.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_netlink_failures_preserve_operation_error_contract(self):
        for error, status, code, message in (
                ("EIO", 500, "command", "The operation failed. Refresh status and check the device over SSH."),
                ("ETIMEDOUT", 504, "timeout", "The operation timed out; refresh status before retrying.")):
            snapshot = self.root / "error.c"
            snapshot.write_text('#include "netlink.h"\n#include <errno.h>\n'
                                f"int vpn_collect(struct vpn_device *d) {{ (void)d; errno = {error}; return -1; }}\n")
            binary = self.root / ("error-native-" + error)
            build(binary, self.root, snapshot)
            actual_code, _, data = self.native(binary=binary)
            self.assertEqual((status, {"ok": False, "error": {"code": code, "message": message}}),
                             (actual_code, data))

    def test_live_peer_fixture_exact_uint64_and_endpoints(self):
        snapshot = self.root / "snapshot.c"
        snapshot.write_text("""#include "netlink.h"
#include <string.h>
int vpn_collect(struct vpn_device *d) {
    memset(d, 0, sizeof(*d)); d->running = true; d->port = 51821;
    strcpy(d->address, "10.6.0.1/24"); d->count = 1;
    memset(d->peers[0].key, 'x', 32);
    d->peers[0].has_handshake = d->peers[0].has_rx = true;
    d->peers[0].has_tx = d->peers[0].has_endpoint = true;
    d->peers[0].handshake = 999820; d->peers[0].rx = UINT64_C(9223372036854775815);
    d->peers[0].tx = UINT64_MAX; strcpy(d->peers[0].endpoint, "[2001:db8::1]:5555");
    return 0;
}
""")
        binary = self.root / "snapshot-native"
        build(binary, self.root, snapshot)
        (self.wg / "wg0.conf").write_text("### begin phone ###\n")
        (self.wg / "configs/clients.txt").write_text(f"phone {KEY} 123 10.6.0.2\n")
        code, _, data = self.native(binary=binary)
        self.assertEqual(200, code)
        self.assertEqual([{"name": "phone", "ip": "10.6.0.2", "created": 123, "enabled": True,
                           "handshake": 999820, "recent": False,
                           "endpoint": "[2001:db8::1]:5555", "rx": 2**63 + 7, "tx": 2**64 - 1}],
                         data["clients"])
        self.assertEqual(51821, self.native("status", binary=binary)[2]["listen_port"])

    def test_production_realtime_clock_preserves_fractional_recent_boundary(self):
        snapshot = self.root / "recent.c"
        snapshot.write_text("""#define _POSIX_C_SOURCE 200809L
#include "netlink.h"
#include <string.h>
#include <time.h>
int vpn_collect(struct vpn_device *d) {
    struct timespec now, pause = {0, 1000000};
    do {
        if (clock_gettime(CLOCK_REALTIME, &now)) return -1;
        if (now.tv_nsec >= 100000000 && now.tv_nsec <= 800000000) break;
        nanosleep(&pause, 0);
    } while (1);
    memset(d, 0, sizeof(*d)); d->running = true; d->count = 1;
    memset(d->peers[0].key, 'x', 32);
    d->peers[0].has_handshake = d->peers[0].has_rx = true;
    d->peers[0].has_tx = d->peers[0].has_endpoint = true;
    d->peers[0].handshake = (uint64_t)now.tv_sec - 180;
    strcpy(d->peers[0].endpoint, "(none)");
    return 0;
}
""")
        binary = self.root / "recent-native"
        build(binary, self.root, snapshot, frozen_clock=False)
        (self.wg / "wg0.conf").write_text("### begin phone ###\n")
        (self.wg / "configs/clients.txt").write_text(f"phone {KEY} 123 10.6.0.2\n")
        data = self.native(binary=binary)[2]
        self.assertFalse(data["clients"][0]["recent"])


class NativeHTTPTests(NativeFixture, unittest.TestCase):
    def setUp(self):
        busybox = os.environ.get("VPN_TEST_BUSYBOX", "busybox")
        if shutil.which(busybox) is None:
            self.skipTest("BusyBox is not available")
        version = subprocess.run([busybox], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, check=False).stdout
        if b"v1.30." in version:
            self.skipTest("BusyBox 1.30 lacks required CGI headers; set VPN_TEST_BUSYBOX")
        if any(name == "wg0" for _, name in socket.if_nameindex()):
            self.skipTest("host wg0 exists; use an isolated network namespace")
        self.fixture()
        self.www = self.root / "www"
        shutil.copytree(OVERLAY / "var/www", self.www)
        cgi = self.www / "cgi-bin/vpn.cgi"
        cgi.parent.mkdir(exist_ok=True)
        cgi.symlink_to(self.binary)
        (self.auth / "auth.conf").unlink()
        (self.run / "sessions" / SID).unlink()
        self.private(self.auth / "setup-token", SID + "\n")
        self.cookie = ""
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.log = (self.root / "http.log").open("w+")
        self.addCleanup(self.log.close)
        config = self.root / "httpd.conf"
        config.write_text((OVERLAY / "etc/httpd.conf").read_text())
        self.server = subprocess.Popen([busybox, "httpd", "-f", "-p", f"127.0.0.1:{self.port}",
                                        "-h", str(self.www), "-c", str(config)],
                                       stdout=self.log, stderr=self.log)
        self.addCleanup(self.stop)
        for _ in range(50):
            if self.server.poll() is not None:
                self.fail("BusyBox exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            self.fail("BusyBox did not become responsive")

    def stop(self):
        self.server.terminate()
        self.server.wait(timeout=5)

    def request(self, route, fields=None):
        from urllib.parse import urlencode
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)) as conn:
            headers = {"Host": "192.168.0.10:8080", "Cookie": self.cookie}
            body = None
            if fields is not None:
                body = urlencode(fields)
                headers.update({"Origin": "http://192.168.0.10:8080", "X-VPN-UI": "1",
                                "Content-Type": "application/x-www-form-urlencoded"})
            conn.request("POST" if fields is not None else "GET",
                         "/cgi-bin/vpn.cgi/" + route, body, headers)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()

    def sign_in(self):
        password = "A unique test 42"
        self.assertEqual(200, self.request("setup", {
            "token": SID, "password": password, "password_confirm": password})[0])
        code, headers, body = self.request("login", {"password": password})
        self.assertEqual(200, code, body)
        self.cookie = headers["Set-Cookie"].split(";")[0]
        # Python issues real uptime; native must read the same precision.
        (self.root / "proc/uptime").write_text(Path("/proc/uptime").read_text())

    def test_real_native_http_authentication_gate_bypass_and_logout(self):
        self.assertEqual(401, self.request("status")[0])
        self.sign_in()
        self.private(self.run / "request.lock", "")
        with (self.run / "request.lock").open("a") as gate:
            fcntl.flock(gate, fcntl.LOCK_EX)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(self.request, ("status", "clients")))
            self.assertEqual([200, 200], [result[0] for result in results])
            self.assertEqual(503, self.request("state")[0])
            self.assertEqual(503, self.request("logout", {})[0])
        self.assertEqual(200, self.request("logout", {})[0])
        self.assertEqual(401, self.request("clients")[0])

    def test_real_native_http_expiry_and_auth_writer_conflict(self):
        self.sign_in()
        with (self.run / "auth.lock").open("a") as auth:
            fcntl.flock(auth, fcntl.LOCK_EX)
            result = self.request("clients")
            self.assertEqual(409, result[0], result[2])
        sid = self.cookie.split("=", 1)[1]
        issued = float((self.run / "sessions" / sid).read_text())
        (self.root / "proc/uptime").write_text(f"{issued + 1800} 0\n")
        self.assertEqual(401, self.request("status")[0])

    def test_real_native_http_logout_race_never_renews_revoked_session(self):
        self.sign_in()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            read = pool.submit(self.request, "clients")
            logout = pool.submit(self.request, "logout", {})
            read_result, logout_result = read.result(), logout.result()
        self.assertIn(read_result[0], (200, 401, 409))
        if logout_result[0] == 409:
            logout_result = self.request("logout", {})
        self.assertEqual(200, logout_result[0], logout_result[2])
        self.assertEqual(401, self.request("status")[0])
        self.assertEqual([], list((self.run / "sessions").iterdir()))


class NativePackageSetupTests(unittest.TestCase):
    def test_registration_is_complete_and_idempotent_for_fresh_and_existing_trees(self):
        installer = ROOT / "sysdrv/tools/board/buildroot/install-custom-packages.sh"
        for existing in ("", '\tsource "package/btop/Config.in"\n',
                         '\tsource "package/vpn-web/Config.in"\n',
                         '\tsource "package/btop/Config.in"\n'
                         '\tsource "package/vpn-web/Config.in"\n'):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                tree = Path(directory)
                (tree / "package").mkdir()
                config = tree / "package/Config.in"
                config.write_text('\tsource "package/bubblewrap/Config.in"\n' + existing)
                for _ in range(2):
                    subprocess.run(["sh", str(installer), str(tree)], check=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    content = config.read_text()
                    for package in ("btop", "vpn-web"):
                        self.assertEqual(1, content.count(f'source "package/{package}/Config.in"'))
                        self.assertTrue((tree / "package" / package / "Config.in").is_file())
                    self.assertLess(content.index('source "package/btop/Config.in"'),
                                    content.index('source "package/vpn-web/Config.in"'))


class NativeImageTests(NativeFixture, unittest.TestCase):
    def setUp(self):
        if not shutil.which("fakeroot"):
            self.skipTest("fakeroot is not available")
        self.fixture()
        self.image_root = self.root / "assembled"
        shutil.copytree(OVERLAY, self.image_root)
        shutil.copyfile(self.binary, self.image_root / "opt/vpn-web/vpn-native")
        self.env = dict(os.environ, RK_PROJECT_PACKAGE_ROOTFS_DIR=str(self.image_root))
        self.hook = ROOT / "project/cfg/BoardConfig_IPC/luckfox-vpn-overlay-post.sh"
        subprocess.run(["bash", str(self.hook)], env=self.env, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def fakeroot(self, *args):
        return subprocess.run(["fakeroot", "--", "bash", str(self.hook), "--image", *args],
                              env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def test_final_native_link_and_obsolete_deployment_files_are_removed(self):
        public = self.image_root / "var/www/cgi-bin/vpn.cgi"
        obsolete = ("etc/vpn-web-backend", "opt/vpn-web/select-backend",
                    "opt/vpn-web/vpn-legacy.cgi")
        for path in obsolete:
            self.assertFalse((OVERLAY / path).exists())
            (self.image_root / path).write_text("obsolete\n")
        public.unlink()
        public.symlink_to("/run/webui/vpn.cgi")
        subprocess.run(["bash", str(self.hook)], env=self.env, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual("/opt/vpn-web/vpn-native", os.readlink(public))
        self.assertEqual("1000.25", (self.run / "sessions" / SID).read_text())
        for path in obsolete:
            self.assertFalse((self.image_root / path).exists())

    def test_ext4_final_binary_configuration_and_link_ownership(self):
        if not shutil.which("mkfs.ext4") or not shutil.which("debugfs"):
            self.skipTest("ext4 image tools are not available")
        image = self.root / "fixture.ext4"
        with image.open("wb") as handle:
            handle.truncate(16 * 1024 * 1024)
        result = self.fakeroot("mkfs.ext4", "-q", "-F", "-d", str(self.image_root), str(image))
        self.assertEqual(0, result.returncode, result.stderr)
        for path in ("/opt/vpn-web/vpn-native", "/etc/httpd.conf",
                     "/var/www/cgi-bin/vpn.cgi"):
            result = subprocess.run(["debugfs", "-R", "stat " + path, str(image)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self.assertRegex(result.stdout.decode(), r"User:\s+0\s+Group:\s+0")
            if path.startswith("/opt"):
                self.assertIn("0755", result.stdout.decode())

    def test_sdk_ext4_pipeline_preserves_fakeroot_ownership(self):
        if not shutil.which("debugfs"):
            self.skipTest("debugfs is not available")
        image = self.root / "sdk-fixture.ext4"
        board = ROOT / "project/cfg/BoardConfig_IPC/BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk"
        configuration = subprocess.run(
            ["bash", "-c", 'source "$1"; printf "%s\\n" "$RK_PROJECT_TOOLS_MKFS_EXT4" "$RK_ROOTFS_IMAGE_SCRIPT"',
             "bash", str(board)], env=dict(self.env, SDK_SYSDRV_DIR=str(ROOT / "sysdrv")),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        formatter, hook = configuration.stdout.decode().splitlines()
        script = Path(formatter)
        self.assertEqual(ROOT / "sysdrv/tools/pc/e2fsprogs/mkfs_ext4.sh", script)
        self.assertEqual(self.hook.name, hook)
        result = self.fakeroot(str(script), str(self.image_root), str(image),
                               str(16 * 1024 * 1024))
        self.assertEqual(0, result.returncode, result.stderr)
        for path in ("/opt", "/var", "/etc", "/etc/init.d",
                     "/opt/vpn-web", "/var/www", "/var/www/cgi-bin",
                     "/opt/vpn-web/vpn-native", "/opt/vpn-web/webui.py", "/etc/httpd.conf",
                     "/etc/init.d/S49httpd", "/var/www/cgi-bin/vpn.cgi"):
            with self.subTest(path=path):
                result = subprocess.run(["debugfs", "-R", "stat " + path, str(image)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                self.assertRegex(result.stdout.decode(), r"User:\s+0\s+Group:\s+0")
                if path in ("/opt/vpn-web/vpn-native", "/etc/init.d/S49httpd"):
                    self.assertIn("0755", result.stdout.decode())
                if path == "/var/www/cgi-bin/vpn.cgi":
                    self.assertIn('/opt/vpn-web/vpn-native', result.stdout.decode())
        self.assertEqual(os.geteuid(), (self.image_root / "etc/httpd.conf").stat().st_uid)

    def test_sdk_formatter_default_is_unchanged_without_vpn_hook(self):
        if not shutil.which("debugfs"):
            self.skipTest("debugfs is not available")
        image = self.root / "default-sdk-fixture.ext4"
        script = ROOT / "sysdrv/tools/pc/e2fsprogs/mkfs_ext4.sh"
        env = dict(self.env)
        env.pop("RK_MKFS_EXT4", None)
        result = subprocess.run([str(script), str(self.image_root), str(image),
                                 str(16 * 1024 * 1024)], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(result.stdout.startswith(b"mkfs.ext4 -d "), result.stdout)
        result = subprocess.run(["debugfs", "-R", "stat /etc/httpd.conf", str(image)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertRegex(result.stdout.decode(), rf"User:\s+{os.geteuid()}\s+Group:\s+{os.getegid()}")


class NativeARMTests(NativeFixture, unittest.TestCase):
    def setUp(self):
        if os.environ.get("VPN_TEST_ARM") != "1":
            self.skipTest("set VPN_TEST_ARM=1 after building the ARM package")
        if any(name == "wg0" for _, name in socket.if_nameindex()):
            self.skipTest("host wg0 exists; use an isolated network namespace")
        self.fixture()

    def test_arm_uclibc_metrics_json_and_storage_arithmetic(self):
        host = ROOT / "sysdrv/source/buildroot/buildroot-2023.02.6/output/host"
        compiler = host / "bin/arm-buildroot-linux-uclibcgnueabihf-gcc"
        sysroot = host / "arm-buildroot-linux-uclibcgnueabihf/sysroot"
        binary = self.root / "arm-native"
        for directory, names in (("lib", ("ld-uClibc.so.0", "ld-uClibc.so.1", "libc.so.0")),
                                 ("usr/lib", ("libjson-c.so.5",))):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
            for name in names:
                source = (sysroot / directory / name).resolve()
                destination = self.root / directory / source.name
                if not destination.exists():
                    shutil.copyfile(source, destination)
                if source.name != name:
                    (self.root / directory / name).symlink_to(source.name)
        with patch.dict(os.environ, VPN_TEST_CC=str(compiler), VPN_TEST_SANITIZERS="0"):
            # QEMU prefixes absolute opens but not subsequent descriptor-relative
            # opens. Use the isolated fixture as its root, including the loader.
            build(binary, "")
        result = subprocess.run(["qemu-arm", "-L", str(self.root), str(binary)],
                                env=dict(os.environ, REQUEST_METHOD="GET", PATH_INFO="/status",
                                         HTTP_COOKIE=self.cookie, QUERY_STRING=""),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=7)
        headers, raw = result.stdout.split(b"\r\n\r\n", 1)
        self.assertIn(b"Status: 200", headers, result.stderr)
        data = json.loads(raw)
        self.assertEqual({"rx": 2**63 + 7, "tx": 2**64 - 1},
                         data["metrics"]["networks"]["eth0"])
        for entry in data["metrics"]["storage"]:
            usage = shutil.disk_usage(self.root / entry["path"].lstrip("/"))
            self.assertEqual((usage.total, usage.used, usage.free),
                             (entry["total"], entry["used"], entry["free"]))


if __name__ == "__main__":
    unittest.main()
