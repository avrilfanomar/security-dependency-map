"""Compare two snapshots: what changed in software, provenance, trust and exposure."""

from __future__ import annotations

from .model import SEV_RANK


def _pkg_key(n):
    a = n["attrs"]
    eco = a.get("ecosystem")
    if eco == "deb":
        return "deb:%s:%s" % (n["label"], a.get("arch"))
    if eco in ("pypi", "npm", "cargo"):
        return "%s:%s:%s:%s" % (eco, a.get("scope") or "", a.get("user") or "", n["label"].lower())
    if eco == "runtime":
        return n["id"]
    return n["id"].split("@")[0]


def diff(old, new):
    on = {n["id"]: n for n in old["nodes"]}
    nn = {n["id"]: n for n in new["nodes"]}
    res = {"from": old["meta"].get("collected_at"), "to": new["meta"].get("collected_at"),
           "host": new["meta"].get("hostname")}

    opk = {_pkg_key(n): n for n in on.values() if n["type"] == "package"}
    npk = {_pkg_key(n): n for n in nn.values() if n["type"] == "package"}
    res["packages_added"] = sorted("%s %s" % (k, npk[k]["attrs"].get("version", "")) for k in set(npk) - set(opk))
    res["packages_removed"] = sorted("%s %s" % (k, opk[k]["attrs"].get("version", "")) for k in set(opk) - set(npk))
    res["packages_changed"] = sorted(
        "%s %s -> %s" % (k, opk[k]["attrs"].get("version"), npk[k]["attrs"].get("version"))
        for k in set(opk) & set(npk) if opk[k]["attrs"].get("version") != npk[k]["attrs"].get("version"))
    res["provenance_changed"] = sorted(
        "%s: %s -> %s" % (k, opk[k]["attrs"].get("origin_class"), npk[k]["attrs"].get("origin_class"))
        for k in set(opk) & set(npk)
        if opk[k]["attrs"].get("origin_class") != npk[k]["attrs"].get("origin_class"))

    for t, key in (("source", "sources"), ("anchor", "anchors"), ("listener", "listeners"), ("vendor", "vendors"),
                   ("service", "services")):
        o = {i for i, n in on.items() if n["type"] == t}
        w = {i for i, n in nn.items() if n["type"] == t}
        res[key + "_added"] = sorted(w - o)
        res[key + "_removed"] = sorted(o - w)
    res["sources_toggled"] = sorted(
        "%s: enabled %s -> %s" % (i, on[i]["attrs"].get("enabled"), nn[i]["attrs"].get("enabled"))
        for i in set(on) & set(nn) if nn[i]["type"] == "source" and on[i]["attrs"].get("enabled") != nn[i]["attrs"].get("enabled"))

    def trust(g, nodes):
        m = {}
        for e in g["edges"]:
            if e["rel"] in ("trusts", "signed_by") and nodes.get(e["src"], {}).get("type") == "source":
                m.setdefault(e["src"], set()).add(e["dst"])
        return m

    ot, nt = trust(old, on), trust(new, nn)
    res["trust_changed"] = sorted(
        "%s: +%s -%s" % (s, sorted(nt.get(s, set()) - ot.get(s, set())), sorted(ot.get(s, set()) - nt.get(s, set())))
        for s in set(ot) & set(nt) if ot[s] != nt[s])

    of = {f["id"]: f for f in old["findings"]}
    nf = {f["id"]: f for f in new["findings"]}
    res["findings_new"] = [{"id": i, "severity": nf[i]["severity"], "title": nf[i]["title"]}
                           for i in sorted(set(nf) - set(of), key=lambda i: SEV_RANK[nf[i]["severity"]])]
    res["findings_resolved"] = [{"id": i, "severity": of[i]["severity"], "title": of[i]["title"]}
                                for i in sorted(set(of) - set(nf), key=lambda i: SEV_RANK[of[i]["severity"]])]
    res["findings_severity_changed"] = ["%s: %s -> %s" % (i, of[i]["severity"], nf[i]["severity"])
                                        for i in set(of) & set(nf) if of[i]["severity"] != nf[i]["severity"]]
    res["empty"] = not any(v for k, v in res.items() if isinstance(v, list))
    return res


def format_text(d):
    lines = ["secdepmap diff for %s: %s -> %s" % (d.get("host"), d.get("from"), d.get("to"))]
    if d["empty"]:
        return lines[0] + "\nNo changes."
    sections = [
        ("New findings", ["[%s] %s" % (f["severity"], f["title"]) for f in d["findings_new"]]),
        ("Resolved findings", ["[%s] %s" % (f["severity"], f["title"]) for f in d["findings_resolved"]]),
        ("Severity changes", d["findings_severity_changed"]),
        ("Trust anchors changed on sources", d["trust_changed"]),
        ("Sources added", d["sources_added"]), ("Sources removed", d["sources_removed"]),
        ("Sources enabled/disabled", d["sources_toggled"]),
        ("Signing keys added", d["anchors_added"]), ("Signing keys removed", d["anchors_removed"]),
        ("Listeners added", d["listeners_added"]), ("Listeners removed", d["listeners_removed"]),
        ("Services added", d["services_added"]), ("Services removed", d["services_removed"]),
        ("Vendors added", d["vendors_added"]), ("Vendors removed", d["vendors_removed"]),
        ("Provenance changed", d["provenance_changed"]),
        ("Packages added", d["packages_added"]), ("Packages removed", d["packages_removed"]),
        ("Packages upgraded/downgraded", d["packages_changed"]),
    ]
    for title, items in sections:
        if items:
            lines.append("\n%s (%d):" % (title, len(items)))
            lines += ["  " + str(x) for x in items[:200]]
            if len(items) > 200:
                lines.append("  ... %d more" % (len(items) - 200))
    return "\n".join(lines)
