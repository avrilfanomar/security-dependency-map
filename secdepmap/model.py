"""Graph model: nodes, edges, findings and per-collector coverage.

Node types (``node["type"]``)
    host, os, kernel, platform, firmware, account,
    vendor, anchor (signing key / trust root), source (repo / store / registry),
    package, service, listener, image

Edge relations (``edge["rel"]``) always point *downstream -> upstream*,
i.e. from the thing that depends to the thing it depends on::

    listener --bound_by--> service --runs--> package --from--> source
    source --signed_by--> anchor --issued_by--> vendor
    source --operated_by--> vendor      package --published_by--> vendor
"""

from __future__ import annotations

import os
import socket
import time

from . import SCHEMA_VERSION, __version__
from .util import IS_ROOT, iso

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self._edge_keys = set()
        self.findings = {}
        self.collectors = {}
        self.meta = {}

    # -- nodes / edges -----------------------------------------------------
    def node(self, nid, ntype, label=None, **attrs):
        n = self.nodes.get(nid)
        if n is None:
            n = {"id": nid, "type": ntype, "label": label or nid, "attrs": {}}
            self.nodes[nid] = n
        elif label:
            n["label"] = label
        for k, v in attrs.items():
            if v is not None:
                n["attrs"][k] = v
        return n

    def has(self, nid):
        return nid in self.nodes

    def edge(self, src, dst, rel, **attrs):
        key = (src, dst, rel)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        e = {"src": src, "dst": dst, "rel": rel}
        e.update({k: v for k, v in attrs.items() if v is not None})
        self.edges.append(e)

    def out_edges(self, nid, rel=None):
        return [e for e in self.edges if e["src"] == nid and (rel is None or e["rel"] == rel)]

    def in_edges(self, nid, rel=None):
        return [e for e in self.edges if e["dst"] == nid and (rel is None or e["rel"] == rel)]

    # -- findings ------------------------------------------------------------
    def finding(self, fid, severity, title, detail="", nodes=(), evidence=None,
                remediation=None, refs=None, category="general"):
        """Record a finding. ``fid`` must be stable across runs (used by diff)."""
        assert severity in SEV_RANK, severity
        f = self.findings.get(fid)
        if f and SEV_RANK[f["severity"]] <= SEV_RANK[severity]:
            # keep the more severe one, merge nodes
            for n in nodes:
                if n not in f["nodes"]:
                    f["nodes"].append(n)
            return f
        f = {
            "id": fid,
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "nodes": list(nodes),
            "evidence": evidence,
            "remediation": remediation,
            "refs": list(refs or []),
        }
        self.findings[fid] = f
        return f

    # -- serialisation -------------------------------------------------------
    def to_dict(self):
        fl = sorted(self.findings.values(), key=lambda f: (SEV_RANK[f["severity"]], f["category"], f["id"]))
        return {
            "schema": SCHEMA_VERSION,
            "tool": {"name": "secdepmap", "version": __version__},
            "meta": self.meta,
            "collectors": self.collectors,
            "nodes": sorted(self.nodes.values(), key=lambda n: (n["type"], n["id"])),
            "edges": self.edges,
            "findings": fl,
            "summary": summarize(self.nodes.values(), fl),
        }


def summarize(nodes, findings):
    by_type, by_eco = {}, {}
    for n in nodes:
        by_type[n["type"]] = by_type.get(n["type"], 0) + 1
        if n["type"] == "package":
            eco = n["attrs"].get("ecosystem", "?")
            by_eco[eco] = by_eco.get(eco, 0) + 1
    sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev[f["severity"]] += 1
    return {"node_types": by_type, "packages_by_ecosystem": by_eco, "findings_by_severity": sev}


class Context:
    """Shared state handed to every collector."""

    def __init__(self, kb, options):
        self.kb = kb
        self.options = options
        self.is_root = IS_ROOT
        self.started = time.time()
        self.shared = {}
        self.hostname = socket.gethostname()
        self.host_id = "host:" + self.hostname
        self._owner_cache = {}

    @property
    def online(self):
        return self.options.get("online", set())

    def users_to_scan(self):
        from .util import current_user_record, human_users

        if self.is_root:
            return human_users()
        return [current_user_record()]

    # -- package-manager ownership of files ----------------------------------
    def resolve_owners(self, paths):
        """Map absolute paths to the owning OS package (dpkg/rpm) or None.

        Scans dpkg's file lists once per batch (no subprocess, works offline,
        handles merged-/usr aliases)."""
        want = {}
        for p in paths:
            if p in self._owner_cache:
                continue
            for alias in _path_aliases(p):
                want.setdefault(alias, set()).add(p)
        if want:
            found = {}
            infodir = "/var/lib/dpkg/info"
            if os.path.isdir(infodir):
                for fn in os.listdir(infodir):
                    if not fn.endswith(".list"):
                        continue
                    pkg = fn[:-5]
                    try:
                        with open(os.path.join(infodir, fn), "r", errors="replace") as fh:
                            for line in fh:
                                line = line.rstrip("\n")
                                if line in want:
                                    for orig in want[line]:
                                        found.setdefault(orig, pkg)
                    except OSError:
                        continue
            elif self.shared.get("rpm_available"):
                from .util import run

                plist = sorted({p for s in want.values() for p in s})
                for i in range(0, len(plist), 200):
                    r = run(["rpm", "-qf", "--qf", "%{NAME}\n"] + plist[i:i + 200], timeout=60)
                    lines = r.out.splitlines()
                    for p, line in zip(plist[i:i + 200], lines):
                        if line and "not owned" not in line:
                            found[p] = line.strip()
            for p in {p for s in want.values() for p in s}:
                self._owner_cache[p] = found.get(p)
        return {p: self._owner_cache.get(p) for p in paths}


def _path_aliases(p):
    out = {p}
    try:
        rp = os.path.realpath(p)
        out.add(rp)
    except OSError:
        rp = p
    for q in list(out):
        for a, b in (("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/lib/", "/lib/"),
                     ("/usr/lib64/", "/lib64/")):
            if q.startswith(a):
                out.add(b + q[len(a):])
            elif q.startswith(b):
                out.add(a + q[len(b):])
    return out


def run_meta(ctx):
    import platform

    return {
        "hostname": ctx.hostname,
        "collected_at": iso(ctx.started),
        "run_as": "root" if ctx.is_root else "user",
        "uid": os.getuid(),
        "python": platform.python_version(),
        "online": sorted(ctx.online),
        "tool_version": __version__,
    }
