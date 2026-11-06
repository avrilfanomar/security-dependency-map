"""Unit tests (stdlib unittest). Run: python3 -m unittest discover -s tests -v"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from secdepmap import diff as sdiff  # noqa: E402
from secdepmap import kb as kbmod  # noqa: E402
from secdepmap import openpgp, util  # noqa: E402
from secdepmap.collectors import apt, services  # noqa: E402
from secdepmap.model import Graph  # noqa: E402
from secdepmap.render import render  # noqa: E402


class AptSources(unittest.TestCase):
    def test_one_line_enabled_disabled_options(self):
        txt = ("deb [arch=amd64 signed-by=/usr/share/keyrings/x.gpg] https://repo.example.com/apt stable main\n"
               "# deb https://old.example.com/apt noble main\n"
               "deb-src http://src.example.com/ubuntu jammy main\n"
               "# just a comment\n")
        e = apt.parse_one_line(txt, "/etc/apt/sources.list.d/x.list")
        e = [x for x in e if x["type"] == "deb"]
        self.assertEqual(len(e), 2)
        self.assertTrue(e[0]["enabled"])
        self.assertEqual(e[0]["options"]["signed-by"], ["/usr/share/keyrings/x.gpg"])
        self.assertFalse(e[1]["enabled"])
        self.assertEqual(e[1]["disabled_reason"], "commented-out")

    def test_deb822(self):
        txt = ("Types: deb\nURIs: https://a.example.com/ubuntu\nSuites: noble noble-updates\nComponents: main\n"
               "Signed-By: /etc/apt/keyrings/a.gpg\nEnabled: no\n")
        e = apt.parse_deb822_sources(txt, "/x.sources")
        self.assertEqual({x["suite"] for x in e}, {"noble", "noble-updates"})
        self.assertTrue(all(not x["enabled"] for x in e))

    def test_ignored_file_is_disabled(self):
        e = apt.parse_one_line("deb https://x.example.com/ stable main\n", "/etc/apt/sources.list.d/x.list.disabled", ignored_file=True)
        self.assertFalse(e[0]["enabled"])
        self.assertEqual(e[0]["disabled_reason"], "ignored-file")

    def test_uri_to_filename_matches_apt(self):
        self.assertEqual(apt.uri_to_filename("http://de.archive.ubuntu.com/ubuntu/dists/resolute-updates/"),
                         "de.archive.ubuntu.com_ubuntu_dists_resolute-updates_")

    def test_list_prefix(self):
        e = {"uri": "https://downloads.claude.ai/claude-desktop/apt/stable", "suite": "stable"}
        self.assertEqual(apt.list_prefix(e), "downloads.claude.ai_claude-desktop_apt_stable_dists_stable_")


class Versions(unittest.TestCase):
    def test_dpkg_compare(self):
        c = util.debian_version_compare
        self.assertEqual(c("1.0", "1.0"), 0)
        self.assertEqual(c("1.0~rc1", "1.0"), -1)
        self.assertEqual(c("1:0.9", "2.0"), 1)
        self.assertEqual(c("3.5.5-1ubuntu3.7", "3.5.5-1ubuntu3.10"), -1)
        self.assertEqual(c("7.0.0-42", "7.0.0-38"), 1)


class SS(unittest.TestCase):
    def test_parse(self):
        out = ('tcp LISTEN 0 511 *:80 *:* uid:0 ino:31505 sk:9 cgroup:/system.slice/apache2.service <->\n'
               'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* uid:104 ino:1 sk:2 cgroup:/system.slice/systemd-resolved.service\n'
               'tcp LISTEN 0 4096 [::1]:631 [::]:* users:(("cupsd",pid=1,fd=7)) cgroup:/system.slice/cups.service\n')
        r = services.parse_ss(out)
        self.assertEqual([x["port"] for x in r], [80, 53, 631])
        self.assertEqual(services.scope_of(r[0]["addr"]), "all-interfaces")
        self.assertEqual(services.scope_of(r[1]["addr"]), "loopback")
        self.assertEqual(services.scope_of(r[2]["addr"]), "loopback")
        self.assertEqual(services.unit_of(r[0]["cgroup"]), ("apache2.service", "system"))
        self.assertEqual(r[2]["procs"][0]["comm"], "cupsd")


@unittest.skipUnless(shutil.which("gpg"), "gpg not installed")
class PGP(unittest.TestCase):
    def test_matches_gpg(self):
        """Our pure-Python parser must give the same fingerprint/expiry/uid as gpg itself."""
        home = tempfile.mkdtemp()
        try:
            env = dict(os.environ, GNUPGHOME=home)
            subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "Test Signer <sec@example.org>",
                            "rsa3072", "sign", "2y"], env=env, check=True, capture_output=True)
            armored = subprocess.run(["gpg", "--armor", "--export"], env=env, check=True, capture_output=True).stdout
            colon = subprocess.run(["gpg", "--with-colons", "--list-keys"], env=env, check=True, capture_output=True, text=True).stdout
            want_fpr = re.search(r"^fpr:+([0-9A-F]{40}):", colon, re.M).group(1)
            want_exp = int(re.search(r"^pub:[^:]*:\d+:\d+:[0-9A-F]+:\d+:(\d+):", colon, re.M).group(1))
            keys = openpgp.parse_keyring(armored)
            self.assertEqual(len(keys), 1)
            k = keys[0]
            self.assertEqual(k["fingerprint"], want_fpr)
            self.assertEqual(k["algo"], "RSA")
            self.assertEqual(k["bits"], 3072)
            self.assertEqual(k["expires"], want_exp)
            self.assertIn("sec@example.org", k["uids"][0])
        finally:
            shutil.rmtree(home, ignore_errors=True)


class DiffTests(unittest.TestCase):
    def snap(self, pkgs, findings=(), enabled=True):
        g = Graph()
        g.meta = {"collected_at": "t", "hostname": "h"}
        for n, v in pkgs.items():
            g.node("pkg:deb:%s:amd64" % n, "package", n, ecosystem="deb", version=v, arch="amd64", origin_class="official")
        g.node("source:apt:x|y", "source", "x", enabled=enabled)
        for fid, sev in findings:
            g.finding(fid, sev, fid)
        return g.to_dict()

    def test_diff(self):
        a = self.snap({"openssl": "1", "curl": "1"}, [("f1", "high")])
        b = self.snap({"openssl": "2", "wget": "1"}, [("f2", "medium")], enabled=False)
        d = sdiff.diff(a, b)
        self.assertEqual(d["packages_added"], ["deb:wget:amd64 1"])
        self.assertEqual(d["packages_removed"], ["deb:curl:amd64 1"])
        self.assertEqual(d["packages_changed"], ["deb:openssl:amd64 1 -> 2"])
        self.assertEqual([f["id"] for f in d["findings_new"]], ["f2"])
        self.assertEqual([f["id"] for f in d["findings_resolved"]], ["f1"])
        self.assertTrue(d["sources_toggled"])
        self.assertTrue(sdiff.diff(a, a)["empty"])


class KBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = kbmod.KB.load()

    def test_schema(self):
        ids = set()
        for vid, v in self.kb.vendors.items():
            self.assertNotIn(vid, ids)
            ids.add(vid)
            self.assertTrue(v.get("name"), vid)
            for kind in (v.get("match") or {}):
                self.assertIn(kind, kbmod.MATCH_KINDS, "%s: unknown match kind %s" % (vid, kind))
            for k, u in (v.get("links") or {}).items():
                self.assertRegex(u, r"^https://", "%s.%s must be https" % (vid, k))
            self.assertTrue(v.get("support_model"), vid)

    def test_matching(self):
        self.assertEqual(self.kb.match("apt_origin", "Ubuntu"), "canonical")
        self.assertEqual(self.kb.match("url_host", "security.ubuntu.com"), "canonical")
        self.assertEqual(self.kb.match("snap_publisher", "mozilla"), "mozilla")
        self.assertEqual(self.kb.vendor_for_domain("deb.debian.org"), "debian")
        self.assertIsNone(self.kb.match("apt_origin", "NoSuchVendor"))

    def test_lifecycle_present(self):
        self.assertIsNotNone(self.kb.lifecycle_for("ubuntu", "24.04"))


class RenderSafety(unittest.TestCase):
    def test_html_escapes_hostile_strings(self):
        g = Graph()
        g.meta = {"hostname": "</script><img src=x onerror=alert(1)>", "collected_at": "t", "run_as": "user",
                  "tool_version": "0", "online": []}
        evil = "</script><script>alert(1)</script><!-- @@JS@@  "
        g.node("pkg:deb:%s:amd64" % evil, "package", evil, ecosystem="deb", version=evil, arch="amd64")
        g.finding("x", "high", evil, evil, nodes=["pkg:deb:%s:amd64" % evil])
        html = render("html", g.to_dict())
        data = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1)
        self.assertNotIn("<", data)
        self.assertNotIn("</script><script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertEqual(html.count("<script"), 2)
        json.loads(data)  # still valid JSON

    def test_markdown_escapes(self):
        g = Graph()
        g.meta = {"hostname": "h", "collected_at": "t", "run_as": "user", "tool_version": "0", "online": []}
        g.finding("x", "high", "a|b <script>", "d")
        md = render("md", g.to_dict())
        self.assertNotIn("<script>", md)


if __name__ == "__main__":
    unittest.main()
