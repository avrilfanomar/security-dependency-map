"""RPM / DNF provenance (EXPERIMENTAL - not exercised on Debian-family CI).

Maps each installed RPM to its Vendor, the key that signed it and the repos
configured in /etc/yum.repos.d. Contributions with test fixtures welcome.
"""

from __future__ import annotations

import configparser
import glob
import os
import re

from ..kb import vendor_node
from ..util import host_of, reg_domain, run, safe_read, which
from . import Status

NAME = "rpm"
DESCRIPTION = "(experimental) RPM packages, signing key per package, dnf/yum repositories and gpgcheck settings"

QF = "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\t%{PACKAGER}\\t%{SIGPGP:pgpsig}\\t%{RSAHEADER:pgpsig}\\t%{FROM_REPO}\\n"


def applicable(ctx):
    if not which("rpm") or os.path.isdir("/var/lib/dpkg"):
        return False, "not an RPM-based system"
    return True, ""


def collect(ctx, g):
    s = Status(notes=["experimental collector"])
    kb = ctx.kb
    ctx.shared["rpm_available"] = True
    repos = {}
    for f in sorted(glob.glob("/etc/yum.repos.d/*.repo")):
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            cp.read_string(safe_read(f) or "")
        except configparser.Error:
            continue
        for sec in cp.sections():
            r = cp[sec]
            uri = r.get("baseurl") or r.get("metalink") or r.get("mirrorlist") or ""
            sid = "source:rpm:" + sec
            enabled = r.get("enabled", "1") == "1"
            gpgcheck = r.get("gpgcheck", "1") == "1"
            repos[sec] = sid
            host = host_of(uri.split()[0] if uri else "")
            g.node(sid, "source", r.get("name", sec), ecosystem="rpm", kind="rpm-repository", uri=uri, file=f,
                   enabled=enabled, gpgcheck=gpgcheck, repo_gpgcheck=r.get("repo_gpgcheck"), gpgkey=r.get("gpgkey"),
                   transport=uri.split(":", 1)[0] if uri else None)
            g.edge(sid, vendor_node(g, kb, kb.vendor_for_domain(host), fallback_domain=reg_domain(host)), "operated_by")
            if enabled and not gpgcheck:
                g.finding("rpm.repo.nogpgcheck:" + sec, "high", "Repository %s has gpgcheck disabled" % sec,
                          nodes=[sid], category="supply-chain")
    r = run(["rpm", "-qa", "--qf", QF], timeout=180)
    unsigned = []
    for line in r.out.splitlines():
        p = line.split("\t")
        if len(p) < 8:
            continue
        name, ver, arch, vendor, packager, sig1, sig2, repo = p
        sig = sig2 if "(none)" not in sig2 else sig1
        keyid = re.search(r"Key ID ([0-9a-fA-F]+)", sig)
        pid = "pkg:rpm:" + name
        g.node(pid, "package", name, ecosystem="rpm", version=ver, arch=arch,
               vendor=None if vendor == "(none)" else vendor, packager=None if packager == "(none)" else packager,
               signing_key=keyid.group(1).upper() if keyid else None, from_repo=None if repo == "(none)" else repo)
        if repo in repos:
            g.edge(pid, repos[repo], "from")
        if keyid:
            aid = "anchor:pgp-keyid:" + keyid.group(1).upper()
            g.node(aid, "anchor", "RPM signing key " + keyid.group(1).upper(), kind="openpgp-key")
            g.edge(pid, aid, "signed_by")
        elif name != "gpg-pubkey":
            unsigned.append(name)
    if unsigned:
        g.finding("rpm.unsigned", "medium", "%d unsigned RPM package(s) installed" % len(unsigned),
                  evidence={"packages": sorted(unsigned)[:300]}, category="supply-chain")
    s.stats["packages"] = len(r.out.splitlines())
    return s
