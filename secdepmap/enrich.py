"""Optional online enrichment (``--online``). Nothing here runs by default.

eol          endoflife.date lifecycle for the OS and Node.js runtimes
securitytxt  RFC 9116 security.txt discovery for every vendor domain in the graph
osv          OSV.dev vulnerability lookup for distro + language packages
             (SENDS PACKAGE NAMES AND VERSIONS TO api.osv.dev)
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .util import iso

UA = "secdepmap/%s (+security inventory; no tracking)" % __version__
MODES = ("eol", "securitytxt", "osv")


def http_get(url, timeout=10, max_bytes=2 * 1024 * 1024, data=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Accept": "application/json, text/plain"})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.geturl(), r.read(max_bytes)


class Cache:
    def __init__(self, path, ttl):
        self.path, self.ttl = path, ttl
        try:
            with open(path) as fh:
                self.data = json.load(fh)
        except (OSError, ValueError):
            self.data = {}

    def get(self, key):
        v = self.data.get(key)
        if v and time.time() - v.get("t", 0) < self.ttl:
            return v.get("v")
        return None

    def put(self, key, value):
        self.data[key] = {"t": time.time(), "v": value}

    def save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as fh:
                json.dump(self.data, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass


def enrich(ctx, g, status):
    modes = ctx.online
    cache = Cache(os.path.join(ctx.options["state_dir"], "online-cache.json") if ctx.options.get("state_dir") else None,
                  ttl=24 * 3600)
    if "eol" in modes:
        _eol(ctx, g, status, cache)
    if "securitytxt" in modes:
        _securitytxt(ctx, g, status, cache)
    if "osv" in modes:
        _osv(ctx, g, status)
    cache.save()


# ---------------------------------------------------------------------------
def _eol(ctx, g, status, cache):
    from .collectors.host import lifecycle_findings

    def fetch(product):
        c = cache.get("eol:" + product)
        if c is not None:
            return c
        try:
            _, _, body = http_get("https://endoflife.date/api/%s.json" % product)
            val = json.loads(body)
        except (urllib.error.URLError, OSError, ValueError) as e:
            status["notes"].append("endoflife.date %s: %s" % (product, e))
            return None
        cache.put("eol:" + product, val)
        return val

    for nid, n in list(g.nodes.items()):
        a = n["attrs"]
        if n["type"] == "os" and a.get("lifecycle_product"):
            cycles = fetch(a["lifecycle_product"])
            if not cycles:
                continue
            ver = a.get("version") or ""
            c = next((x for x in cycles if str(x.get("cycle")) == ver), None) or \
                next((x for x in cycles if str(x.get("cycle")) == ver.split(".")[0]), None)
            if c:
                a["lifecycle"] = dict(c, source="endoflife.date (live)")
                for fid in [f for f in g.findings if f.startswith("os.lifecycle.")]:
                    del g.findings[fid]
                lifecycle_findings(g, nid, n["label"], c)
        elif n["type"] == "package" and a.get("runtime") == "nodejs":
            cycles = fetch("nodejs")
            if cycles:
                major = a["version"].split(".")[0]
                c = next((x for x in cycles if str(x.get("cycle")) == major), None)
                if c:
                    a["lifecycle"] = dict(c, source="endoflife.date (live)")
    status["stats"]["eol"] = "ok"


# ---------------------------------------------------------------------------
SECTXT_FIELDS = ("Contact", "Expires", "Encryption", "Acknowledgments", "Policy", "Preferred-Languages",
                 "Canonical", "Hiring", "CSAF")


def parse_security_txt(text):
    out = {"signed": text.lstrip().startswith("-----BEGIN PGP SIGNED MESSAGE-----")}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z-]+):\s*(.+)$", line.strip())
        if m and m.group(1).title() in [f.title() for f in SECTXT_FIELDS]:
            k = next(f for f in SECTXT_FIELDS if f.title() == m.group(1).title())
            out.setdefault(k, []).append(m.group(2).strip())
    return out


def _securitytxt(ctx, g, status, cache):
    domains = {}
    for nid, n in g.nodes.items():
        if n["type"] == "vendor":
            for d in n["attrs"].get("domains") or []:
                if d:
                    domains.setdefault(d.lower(), []).append(nid)

    def fetch(domain):
        c = cache.get("sectxt:" + domain)
        if c is not None:
            return domain, c
        res = {"found": False}
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                code, final, body = http_get("https://%s%s" % (domain, path), timeout=8, max_bytes=65536)
            except (urllib.error.URLError, OSError, ValueError):
                continue
            text = body.decode("utf-8", "replace")
            if code == 200 and re.search(r"^Contact:", text, re.M | re.I) and "<html" not in text[:500].lower():
                res = dict(parse_security_txt(text), found=True, url=final)
                break
        cache.put("sectxt:" + domain, res)
        return domain, res

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = dict(ex.map(fetch, sorted(domains)))
    found = 0
    for dom, res in results.items():
        for nid in domains[dom]:
            g.nodes[nid]["attrs"].setdefault("security_txt", {})[dom] = res
        if res.get("found"):
            found += 1
            exp = (res.get("Expires") or [None])[0]
            if exp and exp[:10] < iso(time.time())[:10]:
                g.finding("vendor.securitytxt-expired:" + dom, "info", "security.txt of %s is expired (%s)" % (dom, exp),
                          nodes=domains[dom], category="vendor-coverage")
    status["stats"]["security_txt_found"] = "%d/%d domains" % (found, len(results))


# ---------------------------------------------------------------------------
def _osv_ecosystems(ctx, g):
    osr = ctx.shared.get("os_release", {})
    out = []
    if osr.get("ID") == "ubuntu":
        lts = "LTS" in osr.get("VERSION", "")
        base = "Ubuntu:%s%s" % (osr.get("VERSION_ID"), ":LTS" if lts else "")
        out.append(base)
        pro = (g.nodes.get(ctx.host_id, {}).get("attrs", {}).get("ubuntu_pro") or {})
        if not pro.get("attached"):
            out.append("Ubuntu:Pro:%s%s" % (osr.get("VERSION_ID"), ":LTS" if lts else ""))
    elif osr.get("ID") == "debian":
        out.append("Debian:%s" % osr.get("VERSION_ID", "").split(".")[0])
    return out


def _osv(ctx, g, status):
    eco_map = {"pypi": "PyPI", "npm": "npm", "cargo": "crates.io"}
    queries, owners = [], []
    distro_ecos = _osv_ecosystems(ctx, g)
    seen = {}
    for nid, n in g.nodes.items():
        if n["type"] != "package":
            continue
        a = n["attrs"]
        eco = a.get("ecosystem")
        if eco in eco_map and a.get("version"):
            queries.append({"package": {"name": n["label"], "ecosystem": eco_map[eco]}, "version": a["version"]})
            owners.append([nid])
        elif eco == "deb" and distro_ecos and a.get("source_pkg"):
            for de in distro_ecos:
                key = (de, a["source_pkg"], a["source_version"])
                if key in seen:
                    owners[seen[key]].append(nid)
                    continue
                seen[key] = len(queries)
                queries.append({"package": {"name": a["source_pkg"], "ecosystem": de}, "version": a["source_version"]})
                owners.append([nid])
    if not queries:
        return
    vulns_by_q = []
    for i in range(0, len(queries), 1000):
        chunk = queries[i:i + 1000]
        try:
            _, _, body = http_get("https://api.osv.dev/v1/querybatch", timeout=60, max_bytes=64 * 1024 * 1024,
                                  data=json.dumps({"queries": chunk}).encode())
            res = json.loads(body).get("results", [])
        except (urllib.error.URLError, OSError, ValueError) as e:
            status["notes"].append("OSV query failed: %s" % e)
            return
        vulns_by_q += [[v["id"] for v in (r.get("vulns") or [])] for r in res]
    per_eco = {}
    for q, ids, nids in zip(queries, vulns_by_q, owners):
        if not ids:
            continue
        eco = q["package"]["ecosystem"]
        for nid in nids:
            a = g.nodes[nid]["attrs"]
            a.setdefault("osv", {})[eco] = ids
        per_eco.setdefault(eco, []).append(("%s %s" % (q["package"]["name"], q["version"]), len(ids), nids))
    for eco, items in per_eco.items():
        items.sort(key=lambda x: -x[1])
        pro = ":Pro:" in eco
        g.finding("osv:" + eco, "high" if not eco.startswith("Ubuntu") or pro else "medium",
                  "OSV.dev lists known vulnerabilities for %d %s package(s)" % (len(items), eco),
                  ("Ecosystem %s - fixes exist only in Ubuntu Pro (ESM) for many of these." % eco) if pro else
                  "Matches by exact installed version. Distribution records may include CVEs the distro rates as "
                  "negligible or not-affected; check the vendor tracker before acting.",
                  nodes=[n for _, _, ns in items for n in ns][:400],
                  evidence={"top": ["%s: %d" % (k, c) for k, c, _ in items[:40]]},
                  refs=["https://osv.dev"], category="vulnerability")
    status["stats"]["osv_queries"] = len(queries)
    status["stats"]["osv_packages_with_vulns"] = sum(len(v) for v in per_eco.values())
