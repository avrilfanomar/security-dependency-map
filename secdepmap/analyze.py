"""Cross-collector analysis on the finished graph.

* links deferred edges, computes per-node risk (worst finding severity)
* walks exposure chains  listener -> service -> package -> source  to find
  network-facing code with stale or unmaintained provenance
* rolls up 'what each vendor supplies' and flags vendors without a known
  security channel
"""

from __future__ import annotations

from collections import defaultdict

from .model import SEV_RANK


def analyze(ctx, g):
    for src, dst, rel in ctx.shared.get("pending_edges", []):
        if g.has(src) and g.has(dst):
            g.edge(src, dst, rel)
    # drop edges whose endpoints never materialised (e.g. optional anchors)
    g.edges = [e for e in g.edges if e["src"] in g.nodes and e["dst"] in g.nodes]

    out = defaultdict(list)
    inc = defaultdict(list)
    for e in g.edges:
        out[e["src"]].append(e)
        inc[e["dst"]].append(e)

    # ---- exposure chains ------------------------------------------------------
    for lid, ln in list(g.nodes.items()):
        if ln["type"] != "listener" or ln["attrs"].get("scope") in ("loopback", "multicast"):
            continue
        for e1 in out[lid]:
            svc = e1["dst"]
            for e2 in out[svc]:
                if e2["rel"] != "runs":
                    continue
                pkg = g.nodes[e2["dst"]]
                pa = pkg["attrs"]
                g.nodes[e2["dst"]]["attrs"]["network_exposed"] = True
                reason = {
                    "disabled-source": "comes from a disabled repository",
                    "removed-repository": "comes from a removed repository",
                    "distro-leftover": "is a leftover from an older distribution release",
                    "manual": "was installed from a local .deb",
                }.get(pa.get("no_source_reason"))
                if pa.get("ecosystem") == "unmanaged":
                    reason = "is not managed by any package manager"
                if reason:
                    g.finding("chain.exposed-unmaintained:" + e2["dst"], "high",
                              "Network-facing %s %s and receives no updates" % (pkg["label"], reason),
                              "Listener %s -> %s -> %s." % (ln["label"], g.nodes[svc]["label"], pkg["label"]),
                              nodes=[lid, svc, e2["dst"]], category="exposure")
                upd = pa.get("update") or {}
                if upd.get("security") or pa.get("esm_fix"):
                    g.finding("chain.exposed-unpatched:" + e2["dst"], "high",
                              "Network-facing %s has an uninstalled security fix" % pkg["label"],
                              "Listener %s; fix available: %s." % (ln["label"], upd.get("to") or pa.get("esm_fix")),
                              nodes=[lid, svc, e2["dst"]], category="exposure")

    # ---- vendor roll-up ---------------------------------------------------------
    supplies = defaultdict(lambda: {"packages": 0, "by_ecosystem": defaultdict(int), "sources": set(), "anchors": set(),
                                    "network_exposed": 0})
    source_vendor = {}
    for sid, n in g.nodes.items():
        if n["type"] == "source":
            for e in out[sid]:
                if e["rel"] == "operated_by":
                    source_vendor[sid] = e["dst"]
                    supplies[e["dst"]]["sources"].add(sid)
        if n["type"] == "anchor":
            for e in out[sid]:
                if e["rel"] == "issued_by":
                    supplies[e["dst"]]["anchors"].add(sid)
    for pid, n in g.nodes.items():
        if n["type"] != "package":
            continue
        vendors = set()
        for e in out[pid]:
            if e["rel"] == "published_by":
                vendors.add(e["dst"])
            elif e["rel"] == "from" and e["dst"] in source_vendor:
                vendors.add(source_vendor[e["dst"]])
        for v in vendors:
            sp = supplies[v]
            sp["packages"] += 1
            sp["by_ecosystem"][n["attrs"].get("ecosystem", "?")] += 1
            if n["attrs"].get("network_exposed"):
                sp["network_exposed"] += 1
    for vid, sp in supplies.items():
        if vid not in g.nodes:
            continue
        g.nodes[vid]["attrs"]["supplies"] = {
            "packages": sp["packages"], "by_ecosystem": dict(sp["by_ecosystem"]),
            "sources": sorted(sp["sources"]), "anchors": sorted(sp["anchors"]),
            "network_exposed_packages": sp["network_exposed"],
        }
        va = g.nodes[vid]["attrs"]
        links = va.get("links") or {}
        if va.get("pseudo"):
            continue
        if sp["packages"] and not va.get("kb"):
            g.finding("vendor.no-kb:" + vid, "info",
                      "No curated security channel for vendor '%s' (%d package(s))" % (g.nodes[vid]["label"], sp["packages"]),
                      "You depend on this supplier but secdepmap does not know where it publishes advisories. Add it to the "
                      "knowledge base (kb/ or /etc/secdepmap/kb.d/) or run with --online to discover security.txt.",
                      nodes=[vid], category="vendor-coverage")
        elif sp["packages"] and va.get("kb") and va.get("kind") not in ("app-store", "package-registry", "firmware-store") \
                and not (links.get("advisories") or links.get("security")):
            g.finding("vendor.no-advisories:" + vid, "low",
                      "Vendor '%s' has no known public security advisory feed" % g.nodes[vid]["label"],
                      "%d installed package(s) depend on it; vulnerabilities may be fixed silently in new releases." % sp["packages"],
                      nodes=[vid], category="vendor-coverage")

    # ---- risk per node -------------------------------------------------------------
    for f in g.findings.values():
        for nid in f["nodes"]:
            if nid in g.nodes:
                cur = g.nodes[nid].get("risk")
                if cur is None or SEV_RANK[f["severity"]] < SEV_RANK[cur]:
                    g.nodes[nid]["risk"] = f["severity"]
                g.nodes[nid].setdefault("findings", []).append(f["id"])
