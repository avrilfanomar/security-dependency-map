"""Language ecosystems installed outside the OS package manager.

Only *reads files* (dist-info, package.json, .crates2.json, config files) -
never executes pip/npm/cargo, so it is safe to run as root over users' homes.
"""

from __future__ import annotations

import configparser
import glob
import json
import os
import re
import time

from ..kb import vendor_node
from ..util import listdir, parse_date, safe_read
from . import Status

NAME = "lang"
DESCRIPTION = "PyPI (user/system/pipx/uv), npm global + Node.js runtimes (nvm), crates.io (cargo) and rustup; registry configuration"

REGISTRIES = {
    "pypi": ("source:registry:pypi", "PyPI (pypi.org)", "https://pypi.org/simple", "pypi"),
    "npm": ("source:registry:npm", "npm registry (registry.npmjs.org)", "https://registry.npmjs.org", "npm"),
    "cargo": ("source:registry:crates.io", "crates.io", "https://index.crates.io", "crates-io"),
}


def applicable(ctx):
    return True, ""


def _registry(g, kb, eco, uri=None):
    sid, label, default, vid = REGISTRIES[eco]
    if uri and uri.rstrip("/") != default.rstrip("/"):
        sid = "source:registry:%s:%s" % (eco, uri)
        label = "%s mirror/private registry %s" % (eco, uri)
        vnode = vendor_node(g, kb, kb.vendor_for_domain(_host(uri)), fallback_domain=_host(uri))
    else:
        vnode = vendor_node(g, kb, vid if vid in kb.vendors else None, fallback_name=label)
    if not g.has(sid):
        g.node(sid, "source", label, ecosystem=eco, kind="package-registry", uri=uri or default, enabled=True,
               trust_scope="TLS + registry account (no end-to-end package signatures enforced by default)")
        g.edge(sid, vnode, "operated_by")
        anchor = "anchor:webpki"
        g.node(anchor, "anchor", "Web PKI (TLS certificate authorities)", kind="tls-ca",
               detail="Integrity relies on HTTPS to the registry and the security of maintainers' accounts.")
        g.edge(sid, anchor, "signed_by")
    return sid


def _host(uri):
    m = re.match(r"^\w+://([^/:]+)", uri or "")
    return m.group(1) if m else None


def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    users = ctx.users_to_scan()
    totals = {"pypi": 0, "npm": 0, "cargo": 0}
    entrypoints = {}

    # ---------------- Python ----------------
    site_dirs = []
    for d in sorted(glob.glob("/usr/local/lib/python3*/dist-packages") + glob.glob("/usr/local/lib/python3*/site-packages")):
        site_dirs.append((d, "system-pip", None))
    for u in users:
        h = u["home"]
        for d in sorted(glob.glob(h + "/.local/lib/python3*/site-packages")):
            site_dirs.append((d, "user-pip", u["name"]))
        for d in sorted(glob.glob(h + "/.local/share/pipx/venvs/*/lib/python3*/site-packages")):
            site_dirs.append((d, "pipx:" + d.split("/venvs/")[1].split("/")[0], u["name"]))
        for d in sorted(glob.glob(h + "/.local/share/uv/tools/*/lib/python3*/site-packages")):
            site_dirs.append((d, "uv-tool:" + d.split("/tools/")[1].split("/")[0], u["name"]))
    pip_index = _pip_config(g, users)
    reg = None
    py_versions_present = {re.search(r"python(3\.\d+)", x).group(1) for x in os.listdir("/usr/bin") if re.match(r"^python3\.\d+$", x)} \
        if os.path.isdir("/usr/bin") else set()
    orphan_sites = []
    for d, scope, user in site_dirs:
        pyver = re.search(r"python(3\.\d+)", d)
        pyver = pyver.group(1) if pyver else None
        if pyver and py_versions_present and pyver not in py_versions_present and scope == "user-pip":
            orphan_sites.append(d)
        for di in listdir(d):
            if not di.endswith(".dist-info"):
                continue
            meta = safe_read(os.path.join(d, di, "METADATA"), 256 * 1024) or ""
            name = _hdr(meta, "Name")
            ver = _hdr(meta, "Version")
            if not name:
                continue
            installer = (safe_read(os.path.join(d, di, "INSTALLER"), 1024) or "").strip() or None
            direct = safe_read(os.path.join(d, di, "direct_url.json"), 64 * 1024)
            direct_url = None
            if direct:
                try:
                    direct_url = json.loads(direct).get("url")
                except ValueError:
                    pass
            pid = "pkg:pypi:%s:%s@%s" % (scope + (":" + user if user else ""), name.lower(), ver)
            g.node(pid, "package", name, ecosystem="pypi", version=ver, scope=scope, user=user, path=d,
                   installer=installer, direct_url=direct_url, python=pyver,
                   interpreter_missing=(d in orphan_sites) or None)
            if direct_url and not direct_url.startswith("file://"):
                src = "source:direct:" + direct_url.split("#")[0]
                g.node(src, "source", "Direct URL " + direct_url[:80], ecosystem="pypi", kind="direct-url",
                       uri=direct_url, trust_scope="none (not from an index)")
                g.edge(pid, src, "from")
            elif direct_url:
                g.edge(pid, "source:local-build", "from")
                g.node("source:local-build", "source", "Local paths / editable installs", ecosystem="pypi", kind="local")
            else:
                reg = reg or _registry(g, kb, "pypi", pip_index)
                g.edge(pid, reg, "from")
            totals["pypi"] += 1
            ep = safe_read(os.path.join(d, di, "entry_points.txt"), 64 * 1024)
            if ep:
                cp = configparser.ConfigParser(strict=False, interpolation=None)
                try:
                    cp.read_string(ep)
                    for sec in ("console_scripts", "gui_scripts"):
                        if cp.has_section(sec):
                            for script in cp[sec]:
                                entrypoints[script] = pid
                except configparser.Error:
                    pass
    ctx.shared["pip_entrypoints"] = entrypoints
    if orphan_sites:
        g.finding("lang.pypi.orphaned-site", "low",
                  "User Python packages for interpreters that are no longer installed",
                  "Leftover site-packages (%s). Scripts in ~/.local/bin may still reference them; nothing updates them." %
                  ", ".join(orphan_sites), evidence={"paths": orphan_sites}, category="hygiene")
    sys_pip = [d for d, sc, _ in site_dirs if sc == "system-pip" and listdir(d)]
    if sys_pip:
        g.finding("lang.pypi.system-pip", "low", "pip-installed packages in system Python paths",
                  "Packages in %s bypass the OS package manager and can shadow distribution modules used by root tools." %
                  ", ".join(sys_pip), evidence={"paths": sys_pip}, category="hygiene")

    # ---------------- Node / npm ----------------
    npm_cfg = _npm_config(g, users)
    reg_npm = None
    node_dirs = []
    for d in ("/usr/local/lib/node_modules", "/usr/lib/node_modules"):
        node_dirs.append((d, "system", None))
    runtimes = []
    for u in users:
        for nd in sorted(glob.glob(u["home"] + "/.nvm/versions/node/v*")):
            runtimes.append((os.path.basename(nd).lstrip("v"), nd, u["name"]))
            node_dirs.append((nd + "/lib/node_modules", "nvm:" + os.path.basename(nd), u["name"]))
        for extra in (u["home"] + "/.npm-global/lib/node_modules", u["home"] + "/.local/lib/node_modules"):
            node_dirs.append((extra, "user-prefix", u["name"]))
    owned = ctx.resolve_owners([d for d, _, _ in node_dirs if d.startswith("/usr/lib/")])
    for d, scope, user in node_dirs:
        if owned.get(d):
            continue  # distro-packaged node modules are covered by the OS package collector
        for top in listdir(d):
            cands = [os.path.join(d, top)]
            if top.startswith("@"):
                cands = [os.path.join(d, top, x) for x in listdir(os.path.join(d, top))]
            for pdir in cands:
                pj = safe_read(os.path.join(pdir, "package.json"), 512 * 1024)
                if not pj:
                    continue
                try:
                    meta = json.loads(pj)
                except ValueError:
                    continue
                name, ver = meta.get("name"), meta.get("version")
                if not name:
                    continue
                pid = "pkg:npm:%s:%s@%s" % (scope + (":" + user if user else ""), name, ver)
                g.node(pid, "package", name, ecosystem="npm", version=ver, scope=scope, user=user, path=pdir,
                       has_install_scripts=bool(set((meta.get("scripts") or {})) & {"preinstall", "install", "postinstall"}) or None)
                reg_npm = reg_npm or _registry(g, kb, "npm", npm_cfg.get("registry"))
                g.edge(pid, reg_npm, "from")
                totals["npm"] += 1
    for ver, path, user in runtimes:
        rid = "pkg:runtime:nodejs:%s:%s" % (user, ver)
        major = ver.split(".")[0]
        lc = kb.lifecycle_for("nodejs", major)
        g.node(rid, "package", "Node.js " + ver, ecosystem="runtime", runtime="nodejs", version=ver, path=path,
               user=user, installer="nvm", lifecycle=lc)
        src = "source:nodejs-dist"
        if not g.has(src):
            g.node(src, "source", "nodejs.org/dist via nvm", ecosystem="runtime", kind="vendor-download",
                   uri="https://nodejs.org/dist/", trust_scope="TLS + SHASUMS256 (nvm checks checksums, not signatures)")
            g.edge(src, vendor_node(g, kb, "openjs" if "openjs" in kb.vendors else None, fallback_name="OpenJS Foundation"),
                   "operated_by")
            g.edge(src, "anchor:webpki", "signed_by")
        g.edge(rid, src, "from")
        eol = parse_date(lc.get("eol")) if lc and isinstance(lc.get("eol"), str) else None
        if eol and eol < time.time():
            g.finding("lang.nodejs.eol:%s:%s" % (user, ver), "medium", "End-of-life Node.js %s installed via nvm (%s)" % (ver, user),
                      "Node.js %s reached end-of-life on %s and no longer receives security fixes." % (major, lc.get("eol")),
                      nodes=[rid], evidence={"path": path}, remediation="nvm uninstall %s (switch to a supported LTS)" % ver,
                      category="vendor-coverage")
        elif not lc:
            s.note("no lifecycle data for Node.js %s" % major)
    # older patch releases of the same major alongside a newer one
    by_major = {}
    for ver, path, user in runtimes:
        by_major.setdefault((user, ver.split(".")[0]), []).append(ver)
    for (user, major), vers in by_major.items():
        if len(vers) > 1:
            vers.sort(key=lambda v: [int(x) for x in re.findall(r"\d+", v)])
            g.finding("lang.nodejs.stale-patch:%s:%s" % (user, major), "low",
                      "Outdated Node.js %s patch releases kept alongside %s" % (", ".join(vers[:-1]), vers[-1]),
                      "nvm keeps old patch releases; anything still pinned to them (via .nvmrc) runs with known vulnerabilities.",
                      nodes=["pkg:runtime:nodejs:%s:%s" % (user, v) for v in vers[:-1]], category="hygiene")

    # ---------------- Rust ----------------
    for u in users:
        c2 = safe_read(u["home"] + "/.cargo/.crates2.json", 4 * 1024 * 1024)
        if c2:
            try:
                installs = json.loads(c2).get("installs", {})
            except ValueError:
                installs = {}
            for key, info in installs.items():
                m = re.match(r"^(\S+) (\S+) \((.+)\)$", key)
                if not m:
                    continue
                name, ver, srcspec = m.groups()
                pid = "pkg:cargo:%s:%s@%s" % (u["name"], name, ver)
                g.node(pid, "package", name, ecosystem="cargo", version=ver, user=u["name"], source_spec=srcspec,
                       bins=info.get("bins"))
                if srcspec.startswith("registry+") and "crates.io-index" in srcspec or srcspec.startswith("sparse+https://index.crates.io"):
                    g.edge(pid, _registry(g, kb, "cargo"), "from")
                else:
                    sid = "source:direct:" + srcspec
                    g.node(sid, "source", srcspec[:80], ecosystem="cargo", kind="direct-url", uri=srcspec,
                           trust_scope="none (git/path install)")
                    g.edge(pid, sid, "from")
                totals["cargo"] += 1
        for tc in listdir(u["home"] + "/.rustup/toolchains"):
            rid = "pkg:runtime:rust:%s:%s" % (u["name"], tc)
            g.node(rid, "package", "Rust toolchain " + tc, ecosystem="runtime", runtime="rust", version=tc,
                   user=u["name"], installer="rustup")
            src = "source:rustup"
            if not g.has(src):
                g.node(src, "source", "static.rust-lang.org via rustup", ecosystem="runtime", kind="vendor-download",
                       uri="https://static.rust-lang.org", trust_scope="TLS + sha256 manifests")
                g.edge(src, vendor_node(g, kb, "rust" if "rust" in kb.vendors else None, fallback_name="Rust Project"),
                       "operated_by")
                g.edge(src, "anchor:webpki", "signed_by")
            g.edge(rid, src, "from")
    s.stats.update(totals)
    return s


def _hdr(meta, key):
    m = re.search(r"^%s:\s*(.+)$" % re.escape(key), meta, re.M)
    return m.group(1).strip() if m else None


def _pip_config(g, users):
    paths = ["/etc/pip.conf", "/etc/xdg/pip/pip.conf"]
    for u in users:
        paths += [u["home"] + "/.config/pip/pip.conf", u["home"] + "/.pip/pip.conf"]
    index = None
    for p in paths:
        txt = safe_read(p, 64 * 1024)
        if not txt:
            continue
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            cp.read_string(txt)
        except configparser.Error:
            continue
        for sec in cp.sections():
            sect = cp[sec]
            if sect.get("index-url"):
                index = sect.get("index-url").strip()
            if sect.get("extra-index-url"):
                g.finding("lang.pypi.extra-index-url:" + p, "medium", "pip uses extra-index-url (%s)" % p,
                          "pip merges candidates from all indexes and picks the highest version, so a public package with an "
                          "internal name can win (dependency confusion).",
                          evidence={"file": p, "extra-index-url": _redact(sect.get("extra-index-url"))},
                          remediation="Use a single index (proxy) or pin with --index-url + hashes.", category="supply-chain")
            if sect.get("trusted-host"):
                g.finding("lang.pypi.trusted-host:" + p, "medium", "pip trusted-host disables TLS verification (%s)" % p,
                          evidence={"file": p, "trusted-host": sect.get("trusted-host")}, category="transport")
    return _redact(index) if index else None


def _npm_config(g, users):
    out = {}
    paths = ["/etc/npmrc", "/usr/local/etc/npmrc"]
    for u in users:
        paths.append(u["home"] + "/.npmrc")
        paths += glob.glob(u["home"] + "/.nvm/versions/node/*/etc/npmrc")
    for p in paths:
        txt = safe_read(p, 64 * 1024)
        if not txt:
            continue
        keys = {}
        for line in txt.splitlines():
            line = line.strip()
            if not line or line.startswith((";", "#")) or "=" not in line:
                continue
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip()
        if keys.get("registry"):
            out["registry"] = keys["registry"]
        if keys.get("strict-ssl", "").lower() == "false":
            g.finding("lang.npm.strict-ssl-off:" + p, "high", "npm TLS verification disabled (%s)" % p,
                      evidence={"file": p}, category="transport")
        if keys.get("ignore-scripts", "").lower() == "true":
            out["ignore_scripts"] = True
        if any(k.endswith(("_authToken", "_auth", "_password")) for k in keys):
            g.finding("lang.npm.plaintext-token:" + p, "low", "npm registry credential stored in plain text (%s)" % p,
                      "A token in an rc file is readable by any process running as this user (e.g. a malicious install script).",
                      evidence={"file": p, "keys": sorted(k.split(":")[-1] for k in keys if k.endswith(("_authToken", "_auth", "_password")))},
                      remediation="Prefer short-lived tokens / environment injection; restrict file mode to 0600.",
                      category="secrets")
    if users and not out.get("ignore_scripts"):
        out["ignore_scripts"] = False
    return out


def _redact(url):
    return re.sub(r"//[^/@]+@", "//***@", url or "")
