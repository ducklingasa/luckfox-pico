import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
import unittest

from test_vpn_web import OVERLAY


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        binary = self.root / "bin"
        binary.mkdir()
        root = shlex.quote(str(self.root))
        scripts = {
            "mountpoint": "#!/bin/sh\nexit 0\n",
            "python3": "#!/bin/sh\nexit 0\n",
            "vpn-native": "#!/bin/sh\nexit 0\n",
            "stat": '#!/bin/sh\nprintf "0:%s\\n" "$(/usr/bin/stat -c %a "$3")"\n',
            "ip": f"#!/bin/sh\n[ -f {root}/lan-ready ] && echo '2: eth0 inet 192.168.0.10/24 scope global eth0'\nexit 0\n",
            "iptables": f"""#!/bin/sh
if [ "$1" = -C ]; then
    [ -f {root}/old-guard ]
    exit $?
fi
echo "$*" >>{root}/rules
""",
            "httpd": f"""#!/bin/sh
echo ready >{root}/listener
trap 'exit 0' TERM INT
while :; do sleep 1; done
""",
        }
        for name, script in scripts.items():
            path = binary / name
            path.write_text(script)
            path.chmod(0o755)
        self.script = self.root / "S49httpd"
        text = (OVERLAY / "etc/init.d/S49httpd").read_text()
        for old, new in (("/etc/init.d/S49httpd", str(self.script)),
                         ("/run/httpd.pid", str(self.root / "httpd.pid")),
                         ("/run/httpd-control.lock", str(self.root / "control.lock")),
                         ("/var/log/httpd.log", str(self.root / "httpd.log")),
                         ("/usr/bin/python3", str(binary / "python3")),
                         ("/opt/vpn-web/vpn-native", str(binary / "vpn-native")),
                         ("/bin/busybox httpd", str(binary / "httpd"))):
            text = text.replace(old, new)
        self.script.write_text(text)
        self.env = dict(os.environ, PATH=str(binary) + ":/usr/bin:/bin")
        self.addCleanup(self.stop)

    def invoke(self, action):
        return subprocess.run(["/bin/sh", str(self.script), action], env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)

    def stop(self):
        result = self.invoke("stop")
        if result.returncode:
            path = self.root / "httpd.pid"
            if path.exists():
                pid = int(path.read_text())
                if Path(f"/proc/{pid}/cmdline").exists():
                    os.kill(pid, signal.SIGTERM)
            self.fail(result.stderr.decode())

    def test_late_dhcp_recovers_once_and_stop_terminates_listener(self):
        result = self.invoke("start")
        self.assertEqual(0, result.returncode, result.stderr)
        pid = (self.root / "httpd.pid").read_text()
        self.assertFalse((self.root / "listener").exists())
        self.assertEqual(0, self.invoke("start").returncode)
        self.assertEqual(pid, (self.root / "httpd.pid").read_text())
        (self.root / "lan-ready").touch()
        for _ in range(70):
            if (self.root / "listener").exists():
                break
            time.sleep(0.1)
        self.assertTrue((self.root / "listener").exists())
        self.assertEqual(2, len((self.root / "rules").read_text().splitlines()))
        self.stop()
        self.assertFalse((self.root / "httpd.pid").exists())

    def test_stop_cancels_pending_dhcp_retry(self):
        result = self.invoke("start")
        self.assertEqual(0, result.returncode, result.stderr)
        pid = int((self.root / "httpd.pid").read_text())
        self.stop()
        self.assertFalse((self.root / "listener").exists())
        cmdline = Path(f"/proc/{pid}/cmdline")
        self.assertTrue(not cmdline.exists() or not cmdline.read_bytes())

    def test_existing_ingress_guard_is_repositioned_before_listener_start(self):
        (self.root / "old-guard").touch()
        (self.root / "lan-ready").touch()
        result = self.invoke("start")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((self.root / "listener").exists())
        self.assertEqual([
            "-D INPUT ! -i eth0 -p tcp --dport 8080 -j DROP",
            "-I INPUT 1 ! -i eth0 -p tcp --dport 8080 -j DROP",
        ], (self.root / "rules").read_text().splitlines())

    def test_missing_native_backend_stops_before_listener_or_firewall_changes(self):
        (self.root / "lan-ready").touch()
        (self.root / "bin/vpn-native").unlink()
        self.assertNotEqual(0, self.invoke("start").returncode)
        self.assertFalse((self.root / "listener").exists())
        self.assertFalse((self.root / "rules").exists())

    def test_unsafe_native_backend_stops_before_listener_or_firewall_changes(self):
        (self.root / "lan-ready").touch()
        (self.root / "bin/stat").write_text("#!/bin/sh\necho 1000:755\n")
        self.assertNotEqual(0, self.invoke("start").returncode)
        self.assertFalse((self.root / "listener").exists())
        self.assertFalse((self.root / "rules").exists())


if __name__ == "__main__":
    unittest.main()
