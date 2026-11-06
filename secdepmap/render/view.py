"""Build a compact, render-oriented view model from a snapshot.

The map aggregates thousands of packages into per-source groups, keeping
individual nodes only where they matter (risky packages and anything on a
service/exposure chain). Columns, left to right (upstream -> downstream):

    0 vendor   1 trust anchor   2 source   3 software   4 service   5 listener
"""

from __future__ import annotations

from collections import defaultdict

from ..model import SEV_RANK

COL = {"vendor": 0, "anchor": 1, "source": 2, "package": 3, "service": 4, "listener": 5}
INDIVIDUAL_RISKY_CAP = 12


def worst(*sevs):
    sevs = [s for s in sevs if s]
    return min(sevs, key=lambda s: SEV_RANK[s]) if sevs else None


def build(snap, diff=None):
    nodes = {n["id"]: n for n in snap["nodes"]}
    out, inc = defaultdict(list), defaultdict(list)
    for e in snap["edges"]:
        out[e["src"]].append(e)
        inc[e["dst"]].append(e)
    fidx = {f["id"]: f for f in snap["findings"]}

    def label(nid):
        n = nodes.get(nid)
        return n["label"] if n else nid

    def first(nid, rel):
        for e in out[nid]:
            if e["rel"] == rel:
                return e["dst"]
        return None

    # ------------------------------------------------------------------ map
    services = {nid for nid, n in nodes.items() if n["type"] == "service"
                and any(e["rel"] == "bound_by" for e in inc[nid])}
    listeners = {nid for nid, n in nodes.items() if n["type"] == "listener"}
    chain_pkgs = {e["dst"] for s in services for e in out[s] if e["rel"] == "runs"}

    groups = defaultdict(list)  # (source, eco, cls) -> [pkg ids]
    pkg_source = {}
    for nid, n in nodes.items():
        if n["type"] != "package":
            continue
        a = n["attrs"]
        srcs = [e["dst"] for e in out[nid] if e["rel"] == "from"]
        src = srcs[0] if srcs else None
        pkg_source[nid] = src
        cls = a.get("no_source_reason") or a.get("origin_class") or a.get("kind") or ""
        groups[(src, a.get("ecosystem"), cls)].append(nid)

    mnodes, mindex, medges = [], {}, set()
    members = {}

    def add(nid, col, lab, kind, risk=None, count=None, ref=None):
        if nid in mindex:
            return mindex[nid]
        mindex[nid] = len(mnodes)
        mnodes.append({"id": nid, "label": lab, "col": col, "kind": kind, "risk": risk, "count": count,
                       "ref": ref or nid})
        return mindex[nid]

    def edge(a, b, style="solid"):
        if a in mindex and b in mindex and a != b:
            ia, ib = mindex[a], mindex[b]
            if mnodes[ia]["col"] > mnodes[ib]["col"]:
                ia, ib = ib, ia
            medges.add((ia, ib, style))

    pkg_to_map, group_pids = {}, {}
    for (src, eco, cls), pids in groups.items():
        risky = [p for p in pids if nodes[p].get("risk") in ("critical", "high", "medium")]
        indiv = set(p for p in pids if p in chain_pkgs)
        if len(risky) <= INDIVIDUAL_RISKY_CAP:
            indiv |= set(risky)
        if len(pids) <= 3:
            indiv |= set(pids)
        for p in indiv:
            add(p, 3, nodes[p]["label"], "package:" + (eco or "?"), nodes[p].get("risk"))
            pkg_to_map[p] = p
        rest = [p for p in pids if p not in indiv]
        if rest:
            gid = "group:%s|%s|%s" % (src, eco, cls)
            srcl = label(src) if src else "no source"
            add(gid, 3, "%d %s pkgs%s" % (len(rest), eco or "", (" · " + cls) if cls and cls not in ("official",) else ""),
                "group:" + (eco or "?"), worst(*[nodes[p].get("risk") for p in rest]), len(rest), gid)
            group_pids[gid] = rest
            members[gid] = {"label": "%d %s packages from %s" % (len(rest), eco, srcl), "type": "group",
                            "packages": sorted(nodes[p]["label"] + " " + str(nodes[p]["attrs"].get("version") or "") for p in rest)[:2000]}
            for p in rest:
                pkg_to_map[p] = gid

    used_sources = {s for s in pkg_source.values() if s}
    for nid, n in nodes.items():
        if n["type"] == "source" and (n["attrs"].get("enabled") or nid in used_sources):
            add(nid, 2, n["label"], "source:" + (n["attrs"].get("ecosystem") or "?"), n.get("risk"))
    for nid in services:
        add(nid, 4, nodes[nid]["label"], "service", nodes[nid].get("risk"))
    for nid in listeners:
        n = nodes[nid]
        add(nid, 5, n["label"], "listener:" + (n["attrs"].get("scope") or "?"), n.get("risk"))

    # anchors and vendors reachable from what we show
    for nid in [m["id"] for m in mnodes if m["col"] == 2]:
        signed = [e["dst"] for e in out[nid] if e["rel"] == "signed_by"]
        trusts = [e["dst"] for e in out[nid] if e["rel"] == "trusts"]
        for a in signed or trusts:
            if a in nodes:
                add(a, 1, nodes[a]["label"], "anchor", nodes[a].get("risk"))
                edge(a, nid, "solid" if a in signed else "dashed")
        v = first(nid, "operated_by")
        if v in nodes:
            add(v, 0, nodes[v]["label"], "vendor", nodes[v].get("risk"))
            if not (signed or trusts):
                edge(v, nid, "dashed")
    # leftover / risky anchors not reached through a source
    for nid, n in nodes.items():
        if n["type"] == "anchor" and nid not in mindex and n.get("risk") in ("critical", "high", "medium", "low"):
            add(nid, 1, n["label"], "anchor", n.get("risk"))
    for nid in [m["id"] for m in mnodes if m["col"] == 1]:
        v = first(nid, "issued_by")
        if v in nodes:
            add(v, 0, nodes[v]["label"], "vendor", nodes[v].get("risk"))
            edge(v, nid)
    # software -> source, software -> publisher vendor
    for p, m in pkg_to_map.items():
        src = pkg_source.get(p)
        if src in mindex:
            likely = any(e["rel"] == "from" and (e.get("likely") or e.get("outdated")) for e in out[p])
            edge(src, m, "dashed" if likely else "solid")
        for e in out[p]:
            if e["rel"] == "published_by" and e["dst"] in nodes:
                vsrc = first(src, "operated_by") if src else None
                if vsrc != e["dst"]:
                    add(e["dst"], 0, nodes[e["dst"]]["label"], "vendor", nodes[e["dst"]].get("risk"))
                    edge(e["dst"], m, "dotted")
    for s in services:
        for e in out[s]:
            if e["rel"] == "runs" and e["dst"] in pkg_to_map:
                edge(pkg_to_map[e["dst"]], s)
    for l in listeners:
        for e in out[l]:
            if e["rel"] == "bound_by" and e["dst"] in mindex:
                edge(e["dst"], l)
            elif e["rel"] == "bound_by":
                # user process not shown as a service: attach to its package directly
                for e2 in out[e["dst"]]:
                    if e2["rel"] == "runs" and e2["dst"] in pkg_to_map:
                        edge(pkg_to_map[e2["dst"]], l, "dashed")

    # ------------------------------------------------------------------ details
    details = {}

    def detail(nid):
        n = nodes[nid]
        details[nid] = {"label": n["label"], "type": n["type"], "attrs": n["attrs"], "risk": n.get("risk"),
                        "findings": n.get("findings", [])}

    for m in mnodes:
        if m["id"] in nodes:
            detail(m["id"])
    for gid, info in members.items():
        info["findings"] = sorted({f for p in group_pids.get(gid, []) for f in nodes[p].get("findings", [])})
        details[gid] = info
    for nid, n in nodes.items():
        if n["type"] in ("source", "anchor", "vendor", "listener", "service", "host", "os", "kernel", "platform", "firmware"):
            if nid not in details:
                detail(nid)

    # ------------------------------------------------------------------ tables
    def vendor_of_source(sid):
        return label(first(sid, "operated_by")) if sid else ""

    pkg_count = defaultdict(int)
    for p, s in pkg_source.items():
        if s:
            pkg_count[s] += 1
    sources = []
    for nid, n in nodes.items():
        if n["type"] != "source":
            continue
        a = n["attrs"]
        sources.append({
            "id": nid, "label": n["label"], "eco": a.get("ecosystem"), "kind": a.get("kind"), "uri": a.get("uri"),
            "enabled": a.get("enabled"), "disabled_reason": a.get("disabled_reason"), "transport": a.get("transport"),
            "trust": a.get("trust_scope"), "official": a.get("official"), "uu": a.get("unattended_upgrades"),
            "signers": [label(e["dst"]) + " [" + e["dst"].split(":")[-1][-16:] + "]" for e in out[nid] if e["rel"] == "signed_by"],
            "trusts": len([e for e in out[nid] if e["rel"] == "trusts"]),
            "vendor": vendor_of_source(nid), "packages": pkg_count.get(nid, 0), "risk": n.get("risk"),
            "release": {k: (a.get("release") or {}).get(k) for k in ("origin", "label", "date", "valid_until")} if a.get("release") else None,
        })
    sources.sort(key=lambda x: (not x["enabled"], -x["packages"]))
    anchors = []
    for nid, n in nodes.items():
        if n["type"] != "anchor":
            continue
        a = n["attrs"]
        anchors.append({"id": nid, "label": n["label"], "kind": a.get("kind"), "fpr": a.get("fingerprint"),
                        "algo": a.get("algo"), "bits": a.get("bits"), "created": a.get("created"),
                        "expires": a.get("expires"), "scope": a.get("scope"), "files": a.get("files"),
                        "vendor": label(first(nid, "issued_by")),
                        "used_by": sorted(label(e["src"]) for e in inc[nid] if e["rel"] in ("signed_by", "trusts")),
                        "risk": n.get("risk")})
    vendors = []
    for nid, n in nodes.items():
        if n["type"] != "vendor":
            continue
        a = n["attrs"]
        sp = a.get("supplies") or {}
        vendors.append({"id": nid, "label": n["label"], "kind": a.get("kind"), "kb": a.get("kb"), "pseudo": a.get("pseudo"),
                        "packages": sp.get("packages", 0), "by_eco": sp.get("by_ecosystem", {}),
                        "exposed": sp.get("network_exposed_packages", 0),
                        "sources": [label(s) for s in sp.get("sources", [])],
                        "anchors": len(sp.get("anchors", [])), "links": a.get("links") or {},
                        "support": a.get("support_model"), "notes": a.get("notes"), "security_txt": a.get("security_txt"),
                        "verified": a.get("links_verified"), "domains": a.get("domains"), "risk": n.get("risk")})
    vendors.sort(key=lambda v: (-v["packages"], v["label"]))
    exposure = []
    for l in listeners:
        n = nodes[l]
        a = n["attrs"]
        svc = first(l, "bound_by")
        pkg = first(svc, "runs") if svc else None
        src = pkg_source.get(pkg) if pkg else None
        sa = nodes[svc]["attrs"] if svc in nodes else {}
        exposure.append({"id": l, "proto": a.get("proto"), "addr": a.get("address"),
                         "port": a.get("port") if a.get("port") is not None else ("ephemeral (%d)" % len(a.get("ports") or [])),
                         "scope": a.get("scope"), "service": label(svc) if svc else (", ".join(a.get("processes") or []) or "?"),
                         "user": sa.get("user"), "exposure": sa.get("exposure"), "rating": sa.get("exposure_rating"),
                         "package": ("%s %s" % (label(pkg), nodes[pkg]["attrs"].get("version", ""))) if pkg in nodes else "",
                         "source": label(src) if src else "", "vendor": vendor_of_source(src) if src else "",
                         "risk": n.get("risk")})
    exposure.sort(key=lambda x: (x["scope"] == "loopback", x["proto"], x["port"] if isinstance(x["port"], int) else 99999))

    inv_cols = ["name", "version", "eco", "class", "source", "vendor", "risk", "scope", "id"]
    inv = []
    for nid, n in nodes.items():
        if n["type"] != "package":
            continue
        a = n["attrs"]
        src = pkg_source.get(nid)
        pv = next((label(e["dst"]) for e in out[nid] if e["rel"] == "published_by"), None)
        inv.append([n["label"], a.get("version") or "", a.get("ecosystem") or "",
                    a.get("no_source_reason") or a.get("origin_class") or a.get("confinement") or a.get("kind") or "",
                    label(src) if src else "", pv or vendor_of_source(src), n.get("risk") or "",
                    a.get("scope") or a.get("user") or a.get("arch") or "", nid])
    inv.sort(key=lambda r: (SEV_RANK.get(r[6], 9), r[2], r[0].lower()))

    def pick(t):
        return [details[nid] for nid, n in nodes.items() if n["type"] == t and nid in details]

    findings = []
    for f in snap["findings"]:
        findings.append(dict(f, nodes=[{"id": x, "label": label(x), "type": nodes[x]["type"] if x in nodes else "?"}
                                       for x in f["nodes"][:60]], more_nodes=max(0, len(f["nodes"]) - 60)))

    return {
        "meta": snap["meta"], "collectors": snap["collectors"], "summary": snap["summary"],
        "tool": snap.get("tool"), "findings": findings,
        "map": {"nodes": mnodes, "edges": sorted(medges)}, "details": details,
        "sources": sources, "anchors": anchors, "vendors": vendors, "exposure": exposure,
        "inventory": {"cols": inv_cols, "rows": inv},
        "platform": {"host": pick("host"), "os": pick("os"), "kernel": pick("kernel"), "cpu": pick("platform"),
                     "firmware": pick("firmware"), "accounts": [{"label": n["label"], "attrs": n["attrs"]}
                                                                for n in nodes.values() if n["type"] == "account"]},
        "diff": diff,
    }
