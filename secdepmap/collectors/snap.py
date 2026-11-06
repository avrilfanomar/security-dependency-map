"""Snap packages via the snapd REST API (read-only, works unprivileged)."""

from __future__ import annotations

import http.client
import json
import os
import socket

from ..kb import vendor_node
from ..util import run, which
from . import Status

NAME = "snap"
DESCRIPTION = "Snaps: publisher validation, confinement, channel, holds, privileged interface connections"
SOCK = "/run/snapd.socket"

# interfaces whose connection grants (near) root or broad data access
SENSITIVE_IFACES = {
    "snapd-control": "high", "kernel-module-control": "high", "docker-support": "high",
    "system-files": "medium", "block-devices": "high", "mount-control": "high", "firewall-control": "medium",
    "network-control": "medium", "kubernetes-support": "high", "greengrass-support": "high",
    "personal-files": "low", "ssh-keys": "medium", "password-manager-service": "medium",
    "process-control": "medium", "raw-usb": "low", "removable-media": "low", "home": "low",
    "system-observe": "low", "log-observe": "low", "shutdown": "low", "polkit": "medium",
    "steam-support": "medium", "uinput": "medium", "custom-device": "medium", "physical-memory-control": "high",
    "physical-memory-observe": "high", "kernel-firmware-control": "high", "tpm": "medium",
}


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=15):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def api(path):
    c = UnixHTTP(SOCK)
    try:
        c.request("GET", path, headers={"Accept": "application/json"})
        r = c.getresponse()
        data = json.loads(r.read().decode("utf-8", "replace"))
        return data.get("result")
    finally:
        c.close()


def applicable(ctx):
    if os.path.exists(SOCK) or which("snap"):
        return True, ""
    return False, "snapd not installed"


def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    try:
        snaps = api("/v2/snaps") or []
        sysinfo = api("/v2/system-info") or {}
        conns = (api("/v2/connections") or {}).get("established", [])
    except (OSError, ValueError, http.client.HTTPException) as e:
        s.partial("snapd API unavailable (%s); falling back to 'snap list'" % e)
        snaps, sysinfo, conns = _fallback_list(), {}, []
        if not snaps:
            return Status("skipped", ["snapd not reachable"])

    store = sysinfo.get("store") or "snapcraft.io"
    src = "source:snap:" + store
    refresh = sysinfo.get("refresh", {})
    g.node(src, "source", "Snap Store (%s)" % store, ecosystem="snap", kind="app-store", enabled=True,
           uri="https://" + ("snapcraft.io" if store == "snapcraft.io" else store),
           refresh=refresh or None, snapd_version=sysinfo.get("version"), official=True,
           trust_scope="store assertions")
    anchor = "anchor:snap:assertions-root"
    g.node(anchor, "anchor", "Snap assertion root (Canonical)", kind="assertion-root",
           detail="Each snap revision is verified against signed snap-declaration/snap-revision assertions "
                  "chained to Canonical's root key.")
    canonical = vendor_node(g, kb, kb.match("snap_publisher", "canonical"), fallback_name="Canonical")
    g.edge(src, anchor, "signed_by")
    g.edge(src, canonical, "operated_by")
    g.edge(anchor, canonical, "issued_by")
    if refresh.get("hold"):
        g.finding("snap.refresh.held", "medium", "Automatic snap refreshes are held until %s" % refresh.get("hold"),
                  nodes=[src], category="patching")

    plugs, manual = {}, set()
    for c in conns:
        sn_name = c.get("plug", {}).get("snap")
        plugs.setdefault(sn_name, []).append(c.get("interface"))
        if c.get("manual"):
            manual.add((sn_name, c.get("interface")))

    classic, unverified, dangerous, devmode, held = [], [], [], [], []
    auto_priv = {}
    for sn in snaps:
        name = sn.get("name")
        pid = "pkg:snap:" + name
        pub = sn.get("publisher") or {}
        val = pub.get("validation", "unproven")
        conf = sn.get("confinement")
        rev = str(sn.get("revision", ""))
        ifaces = sorted(set(plugs.get(name, [])))
        sens = {i: SENSITIVE_IFACES[i] for i in ifaces if i in SENSITIVE_IFACES}
        auto = sorted(i for i in sens if (name, i) not in manual)
        g.node(pid, "package", name, ecosystem="snap", version=sn.get("version"), revision=rev,
               channel=sn.get("channel"), tracking=sn.get("tracking-channel"), confinement=conf,
               devmode=sn.get("devmode") or None, snap_type=sn.get("type"), publisher=pub.get("username"),
               publisher_validation=val, base=sn.get("base"), install_date=sn.get("install-date"),
               hold=sn.get("hold"), contact=sn.get("contact") or None, website=sn.get("website") or None,
               license=sn.get("license") or None, interfaces=ifaces or None, sensitive_interfaces=sens or None,
               auto_connected_sensitive=auto or None)
        if rev.startswith("x"):
            dangerous.append(name)
            g.edge(pid, "source:snap:local", "from")
            g.node("source:snap:local", "source", "Sideloaded snaps (--dangerous)", ecosystem="snap", kind="local",
                   enabled=True, trust_scope="none")
        else:
            g.edge(pid, src, "from")
        pv = kb.match("snap_publisher", pub.get("username") or pub.get("id"))
        pubnode = vendor_node(g, kb, pv, fallback_name=pub.get("display-name") or pub.get("username"),
                              fallback_domain=None)
        g.nodes[pubnode]["attrs"].setdefault("snap_publisher", pub.get("username"))
        g.nodes[pubnode]["attrs"]["snap_validation"] = val
        g.edge(pid, pubnode, "published_by")
        if conf == "classic":
            classic.append(name)
        if sn.get("devmode") or conf == "devmode":
            devmode.append(name)
        if val not in ("verified", "starred") and sn.get("type") == "app":
            unverified.append(name)
        if sn.get("hold"):
            held.append(name)
        for iface, sev in sens.items():
            if (name, iface) in manual and sev in ("high", "medium", "low"):
                g.finding("snap.iface.%s:%s" % (iface, name), sev,
                          "Snap '%s' was manually connected to privileged interface '%s'" % (name, iface),
                          "A user/admin widened this snap's sandbox; '%s' grants access well beyond the app's own data." % iface,
                          nodes=[pid], remediation="snap disconnect %s:%s" % (name, iface), category="sandbox")
            elif sev == "high":
                auto_priv.setdefault(name, []).append(iface)

    if auto_priv:
        g.finding("snap.iface.auto-privileged", "info",
                  "%d snap(s) hold store-granted privileged interfaces: %s" % (
                      len(auto_priv), ", ".join("%s(%s)" % (k, "/".join(v)) for k, v in sorted(auto_priv.items()))),
                  "Auto-connected via the publisher's snap-declaration after Snap Store review - expected for these "
                  "apps, but they are high-value targets: a compromised publisher could abuse the access.",
                  nodes=["pkg:snap:" + n for n in auto_priv], category="sandbox")
    if classic:
        g.finding("snap.classic", "medium", "%d classic (unconfined) snap(s): %s" % (len(classic), ", ".join(classic)),
                  "Classic snaps run without the snap sandbox, with the same access as a traditionally installed program; "
                  "a compromised publisher account or build reaches your whole user session (and root if run via sudo).",
                  nodes=["pkg:snap:" + n for n in classic], category="sandbox")
    if devmode:
        g.finding("snap.devmode", "high", "Snap(s) installed in devmode: %s" % ", ".join(devmode),
                  "devmode disables confinement and enforcement entirely.", nodes=["pkg:snap:" + n for n in devmode],
                  category="sandbox")
    if dangerous:
        g.finding("snap.dangerous", "high", "Sideloaded snap(s) without store signature: %s" % ", ".join(dangerous),
                  "Installed with --dangerous: no assertion verification and no automatic updates.",
                  nodes=["pkg:snap:" + n for n in dangerous], category="supply-chain")
    if unverified:
        g.finding("snap.publisher.unverified", "low",
                  "%d snap(s) from publishers without a verified/starred identity: %s" % (len(unverified), ", ".join(unverified)),
                  "The Snap Store has not verified who operates these publisher accounts.",
                  nodes=["pkg:snap:" + n for n in unverified], category="supply-chain")
    if held:
        g.finding("snap.held", "medium", "Snap(s) with refresh on hold: %s" % ", ".join(held),
                  nodes=["pkg:snap:" + n for n in held], category="patching")
    s.stats.update(snaps=len(snaps), classic=len(classic), unverified=len(unverified))
    return s


def _fallback_list():
    r = run(["snap", "list", "--unicode=never", "--color=never"], timeout=30)
    out = []
    for line in r.out.splitlines()[1:]:
        p = line.split()
        if len(p) < 5:
            continue
        notes = p[5] if len(p) > 5 else ""
        pubraw = p[4]
        val = "verified" if pubraw.endswith("**") else ("starred" if pubraw.endswith("*") else "unproven")
        out.append({"name": p[0], "version": p[1], "revision": p[2], "tracking-channel": p[3],
                    "publisher": {"username": pubraw.rstrip("*"), "validation": val},
                    "confinement": "classic" if "classic" in notes else "strict",
                    "devmode": "devmode" in notes, "type": "app" if notes in ("-", "classic") else notes})
    return out
