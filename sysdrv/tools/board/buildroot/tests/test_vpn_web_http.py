"""Host BusyBox transport test using private temporary state, never host VPN state."""

import base64
import http.client
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import time
import unittest
from urllib.parse import urlencode

from test_vpn_web import OVERLAY
from test_vpn_web_native import NativeFixture


class HTTPTests(NativeFixture, unittest.TestCase):
    def setUp(self):
        busybox = os.environ.get("VPN_TEST_BUSYBOX", "busybox")
        if shutil.which(busybox) is None:
            self.skipTest("BusyBox is not available")
        version = subprocess.run([busybox], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False).stdout
        if b"v1.30." in version:
            self.skipTest("BusyBox 1.30 does not export the required CGI headers; use VPN_TEST_BUSYBOX=1.36.1-binary")
        if any(name == "wg0" for _, name in socket.if_nameindex()):
            self.skipTest("host wg0 exists; use an isolated network namespace")
        self.fixture()
        root = self.root
        www = root / "www"
        shutil.copytree(OVERLAY / "var/www", www)
        (self.auth / "auth.conf").unlink()
        (self.run / "sessions" / ("a" * 64)).unlink()
        self.private(self.auth / "setup-token", "a" * 64 + "\n")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", int(os.environ.get("VPN_TEST_PORT", "0"))))
            self.port = sock.getsockname()[1]
        cgi = www / "cgi-bin/vpn.cgi"
        cgi.parent.mkdir(exist_ok=True)
        cgi.symlink_to(self.binary)
        (root / "httpd.conf").write_text((OVERLAY / "etc/httpd.conf").read_text())
        self.log = (root / "http.log").open("w+")
        self.addCleanup(self.log.close)
        self.server = subprocess.Popen(
            [busybox, "httpd", "-f", "-p", "127.0.0.1:" + str(self.port),
             "-h", str(www), "-c", str(root / "httpd.conf")],
            stdout=self.log, stderr=self.log)
        self.addCleanup(self.stop)
        for _ in range(50):
            if self.server.poll() is not None:
                self.fail("BusyBox HTTP server failed to start")
            try:
                connection = socket.create_connection(("127.0.0.1", self.port), timeout=0.1)
                connection.close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            self.fail("BusyBox HTTP server did not become ready")
        self.cookie = ""

    def stop(self):
        self.server.terminate()
        self.server.wait(timeout=5)

    def request(self, route, fields=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        body = fields if isinstance(fields, bytes) else urlencode(fields) if fields is not None else None
        supplied = {"Host": "192.168.0.10:8080", "Cookie": self.cookie}
        if fields is not None:
            supplied.update({"Origin": "http://192.168.0.10:8080", "X-VPN-UI": "1",
                             "Content-Type": "application/x-www-form-urlencoded"})
        supplied.update(headers or {})
        connection.request("POST" if fields is not None else "GET",
                           "/cgi-bin/vpn.cgi/" + route, body, supplied)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        if route == "login" and result[0] == 200:
            (self.root / "proc/uptime").write_text(Path("/proc/uptime").read_text())
        return result

    def test_setup_login_private_app_status_logout_over_http(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", "/")
        root_response = connection.getresponse()
        root_body = root_response.read()
        connection.close()
        self.assertEqual(200, root_response.status, root_body)
        self.assertIn(b"login.js", root_body)
        code, headers, body = self.request("state")
        self.assertEqual(200, code, body)
        self.assertTrue(json.loads(body)["setup"])
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertEqual(302, self.request("app")[0])
        fields = {"token": "a" * 64, "password": "A unique test 42",
                  "password_confirm": "A unique test 42"}
        result = self.request("setup", fields)
        self.assertEqual(200, result[0], result[2])
        result = self.request("login", {"password": fields["password"]})
        self.assertEqual(200, result[0], result[2])
        self.cookie = result[1]["Set-Cookie"].split(";")[0]
        code, headers, body = self.request("app")
        self.assertEqual(200, code, body)
        self.assertIn(b"VPN CONTROL CENTER", body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        code, _, body = self.request("status")
        self.assertEqual(200, code, body)
        self.assertFalse(json.loads(body)["running"])
        self.assertEqual(403, self.request("logout", {}, {"Origin": "https://evil.test"})[0])
        result = self.request("logout", {})
        self.assertEqual(200, result[0], result[2])
        self.assertIn("Max-Age=0", result[1]["Set-Cookie"])
        self.assertEqual(302, self.request("app")[0])
        self.assertEqual(401, self.request("status")[0])
        self.assertEqual(200, self.request("logout", {})[0])

    def test_request_gate_reports_busy_with_bounded_wait(self):
        self.private(self.run / "request.lock", "")
        with (self.run / "request.lock").open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            started = time.monotonic()
            result = self.request("state")
            self.assertEqual(503, result[0], result[2])
            self.assertEqual("busy", json.loads(result[2])["error"]["code"])
            self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(200, self.request("state")[0])

    def test_upload_keeps_filename_and_validates_before_replacement_over_http(self):
        fields = {"token": "a" * 64, "password": "A unique test 42",
                  "password_confirm": "A unique test 42"}
        self.assertEqual(200, self.request("setup", fields)[0])
        result = self.request("login", {"password": fields["password"]})
        self.assertEqual(200, result[0], result[2])
        self.cookie = result[1]["Set-Cookie"].split(";")[0]
        key = base64.b64encode(b"x" * 32).decode()
        files = {
            "userdata/wireguard/wg0.conf": "[Interface]\nPrivateKey = " + key + "\nAddress = 10.6.0.1/24\n",
            "userdata/wireguard/server_priv": key + "\n",
            "userdata/wireguard/server_pub": key + "\n",
            "userdata/wireguard/configs/clients.txt": "",
            "etc/pivpn/wireguard/setupVars.conf":
                (OVERLAY / "etc/pivpn/wireguard/setupVars.conf").read_text()}
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode="w:gz", format=tarfile.USTAR_FORMAT) as target:
            for name, value in files.items():
                member = tarfile.TarInfo(name)
                data = value.encode()
                member.size = len(data)
                target.addfile(member, io.BytesIO(data))
        payload = source.getvalue()
        name = "pivpnbackup-20261022-100716.tgz"
        destination = self.backups / name
        destination.write_bytes(b"existing backup")
        os.utime(destination, (1000, 1000))
        headers = {"Content-Type": "application/gzip", "X-VPN-Backup-Name": name}
        result = self.request("backup-upload", b"junk", headers)
        self.assertEqual(400, result[0], result[2])
        self.assertEqual("archive", json.loads(result[2])["error"]["code"])
        self.assertEqual(b"existing backup", destination.read_bytes())
        result = self.request("backup-upload", payload, headers)
        self.assertEqual(200, result[0], result[2])
        self.assertEqual(name, json.loads(result[2])["file"])
        listed = self.request("backups")
        self.assertEqual(200, listed[0], listed[2])
        rows = json.loads(listed[2])["backups"]
        self.assertEqual([name], [row["file"] for row in rows])
        self.assertGreater(rows[0]["modified"], 1000)
        downloaded = self.request("backup-download?file=" + name)
        self.assertEqual(200, downloaded[0], downloaded[2])
        self.assertEqual(payload, downloaded[2])
        self.assertEqual([destination], list(self.backups.iterdir()))


if __name__ == "__main__":
    if sys.argv[1:] == ["--preview"]:
        fixture = HTTPTests()
        try:
            fixture.setUp()
            print(f"Preview: http://127.0.0.1:{fixture.port} (temporary state: {fixture.root})", flush=True)
            time.sleep(300)
        finally:
            fixture.doCleanups()
    else:
        unittest.main()
