"""Flatpak apps & runtimes: remotes, GPG verification, sandbox holes, EOL runtimes."""

from __future__ import annotations

import configparser
import os
import re

from ..kb import vendor_node
from ..util import host_of, reg_domain, run, safe_read, which
from . import Status

NAME = "flatpak"
DESCRIPTION = "Flatpak remotes (GPG verification), apps/runtimes, static sandbox permissions, end-of-life runtimes"

# permission -> (severity, why). Checked against `flatpak info --show-permissions`.
RISKY = [
    (r"^filesystems=.*\bhost(?::rw)?(;|$)", "medium", "full host filesystem access (filesystem=host)"),
    (r"^filesystems=.*\bhost-os\b", "medium", "access to host OS files (filesystem=host-os)"),
    (r"^filesystems=.*\bhost-etc\b", "medium", "access to host /etc (filesystem=host-etc)"),
    (r"^filesystems=.*(\bhome\b|~/?(;|$))", "low", "read/write access to the whole home directory"),
    (r"^devices=.*\ball\b", "low", "access to all devices (devices=all: webcams, USB, GPUs)"),
    (r"^sockets=.*(?<!fallback-)\bx11\b", "low", "X11 socket - can snoop keystrokes/screens of other X11 apps"),
    (r"^sockets=.*\bssh-auth\b", "medium", "can use your SSH agent"),
    (r"^sockets=.*\bsystem-bus\b", "medium", "unfiltered system D-Bus access"),
    (r"^sockets=.*\bsession-bus\b", "medium", "unfiltered session D-Bus access"),
    (r"^org\.freedesktop\.Flatpak=talk", "high", "can talk to org.freedesktop.Flatpak - run arbitrary commands on the host (sandbox escape)"),
    (r"^org\.freedesktop\.secrets=talk", "low", "access to the desktop keyring (Secret Service)"),
    (r"^features=.*\bdevel\b", "low", "ptrace/perf allowed (features=devel)"),
]


def applicable(ctx):
    return (True, "") if which("flatpak") else (False, "flatpak not installed")


def _remote_configs(users):
    """Parse ostree repo configs for gpg-verify settings."""
    out = {}
    paths = ["/var/lib/flatpak/repo/config"]
    for u in users:
        paths.append(os.path.join(u["home"], ".local/share/flatpak/repo/config"))
    for p in paths:
        txt = safe_read(p)
        if not txt:
            continue
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            cp.read_string(txt)
        except configparser.Error:
            continue
        inst = "system" if p.startswith("/var/") else "user"
        for sec in cp.sections():
            m = re.match(r'remote "(.+)"', sec)
            if m:
                out[(inst, m.group(1))] = dict(cp[sec])
    return out


def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    cfgs = _remote_configs(ctx.users_to_scan())

    r = run(["flatpak", "remotes", "--columns=name,url,options,title"], timeout=30)
    remotes = {}
    for line in r.out.splitlines():
        p = line.split("\t")
        if len(p) < 2:
            continue
        name, url = p[0], p[1]
        opts = p[2] if len(p) > 2 else ""
        inst = "user" if "user" in opts else "system"
        cfg = cfgs.get((inst, name), {})
        rid = "source:flatpak:%s:%s" % (inst, name)
        gpg = cfg.get("gpg-verify", "true").lower() != "false"
        gpg_sum = cfg.get("gpg-verify-summary", "true").lower() != "false"
        remotes[name] = rid
        host = host_of(url)
        vid = kb.match("flatpak_remote", name) or kb.vendor_for_domain(host)
        g.node(rid, "source", "Flatpak remote %s (%s)" % (name, inst), ecosystem="flatpak", kind="app-store",
               uri=url, enabled="disabled" not in opts, installation=inst, gpg_verify=gpg,
               gpg_verify_summary=gpg_sum, collection_id=cfg.get("collection-id"),
               transport=url.split(":", 1)[0], trust_scope="remote GPG key" if gpg else "none")
        g.edge(rid, vendor_node(g, kb, vid, fallback_domain=reg_domain(host)), "operated_by")
        aid = "anchor:flatpak:%s:%s" % (inst, name)
        g.node(aid, "anchor", "GPG key of flatpak remote '%s'" % name, kind="flatpak-remote-key",
               configured=gpg, keyring="/var/lib/flatpak/repo/%s.trustedkeys.gpg" % name if inst == "system" else None)
        if gpg:
            g.edge(rid, aid, "signed_by")
            g.edge(aid, vendor_node(g, kb, vid, fallback_domain=reg_domain(host)), "issued_by")
        else:
            g.finding("flatpak.remote.no-gpg:" + name, "high", "Flatpak remote '%s' has GPG verification disabled" % name,
                      nodes=[rid], remediation="flatpak remote-modify --gpg-verify %s" % name, category="supply-chain")
        if url.startswith("http://"):
            g.finding("flatpak.remote.http:" + name, "low", "Flatpak remote '%s' uses plain HTTP" % name,
                      nodes=[rid], category="transport")

    cols = "application,branch,version,origin,installation,arch,ref,runtime,name"
    apps = _list(["flatpak", "list", "--app", "--columns=" + cols])
    rts = _list(["flatpak", "list", "--runtime", "--columns=" + cols])
    used_runtimes = {}
    for a in apps:
        if a.get("runtime"):
            used_runtimes.setdefault(a["runtime"].split("/")[0] + "//" + a["runtime"].split("/")[-1], []).append(a["application"])

    def eol_of(item):
        ref = ("app/" if item in apps else "runtime/") + item["ref"]
        rr = run(["flatpak", "remote-info", "--cached", "--" + item["installation"], item["origin"], ref], timeout=30)
        m = re.search(r"^\s*End-of-life(?:-rebase)?:\s*(.+)$", rr.out, re.M)
        return item["ref"], (m.group(1).strip() if m else None)

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=6) as ex:
        eol = {ref: why for ref, why in ex.map(eol_of, apps + rts) if why}

    risky_apps = 0
    for item in apps + rts:
        is_app = item in apps
        app = item["application"]
        pid = "pkg:flatpak:%s//%s" % (app, item["branch"])
        perms, risks = None, []
        if is_app:
            pr = run(["flatpak", "info", "--show-permissions", "--" + item["installation"], app], timeout=20)
            perms = pr.out.strip() or None
            for line in (perms or "").splitlines():
                line = line.strip()
                for rx, sev, why in RISKY:
                    if re.search(rx, line):
                        risks.append({"severity": sev, "why": why, "line": line})
        rid = remotes.get(item["origin"], "source:flatpak:%s:%s" % (item["installation"], item["origin"]))
        g.node(pid, "package", item.get("name") or app, ecosystem="flatpak", app_id=app, version=item.get("version") or None,
               branch=item["branch"], kind="app" if is_app else "runtime", origin=item["origin"],
               installation=item["installation"], runtime=item.get("runtime") or None,
               permissions=perms, sandbox_risks=risks or None, eol=eol.get(item["ref"]),
               used_by=used_runtimes.get(app + "//" + item["branch"]) if not is_app else None)
        if not g.has(rid):
            g.node(rid, "source", "Flatpak remote %s" % item["origin"], ecosystem="flatpak", kind="app-store")
        g.edge(pid, rid, "from")
        if is_app:
            pv = kb.match("flatpak_app", app)
            if pv:
                g.edge(pid, vendor_node(g, kb, pv), "published_by")
            if item.get("runtime"):
                rt_id, rt_branch = item["runtime"].split("/")[0], item["runtime"].split("/")[-1]
                g.edge(pid, "pkg:flatpak:%s//%s" % (rt_id, rt_branch), "depends_on")
        worst = sorted(risks, key=lambda x: ["high", "medium", "low"].index(x["severity"]))
        if worst:
            risky_apps += 1
            sev = worst[0]["severity"]
            g.finding("flatpak.sandbox:" + app, sev,
                      "Flatpak '%s' has broad sandbox permissions" % (item.get("name") or app),
                      "; ".join(sorted({w["why"] for w in worst})),
                      nodes=[pid], evidence={"permissions": [w["line"] for w in worst]},
                      remediation="Restrict with: flatpak override --user --nofilesystem=host %s (adjust per permission)" % app,
                      category="sandbox")
        if item["ref"] in eol:
            g.finding("flatpak.eol:" + item["ref"], "medium" if (is_app or used_runtimes.get(app + "//" + item["branch"])) else "low",
                      "End-of-life Flatpak %s: %s//%s" % ("app" if is_app else "runtime", app, item["branch"]),
                      eol[item["ref"]], nodes=[pid],
                      remediation="flatpak update; flatpak uninstall --unused", category="vendor-coverage")
    s.stats.update(apps=len(apps), runtimes=len(rts), remotes=len(remotes), eol=len(eol), risky_apps=risky_apps)
    return s


def _list(argv):
    r = run(argv, timeout=60)
    keys = argv[-1].split("=", 1)[1].split(",")
    out = []
    for line in r.out.splitlines():
        p = line.split("\t")
        if len(p) < len(keys) - 1:
            continue
        out.append(dict(zip(keys, p + [""] * (len(keys) - len(p)))))
    return out
