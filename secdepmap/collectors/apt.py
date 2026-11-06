"""APT / dpkg: sources, trust anchors, package provenance, update coverage.

Builds:  package --from--> source --signed_by--> anchor(pgp key) --issued_by--> vendor
                                  --operated_by--> vendor
"""

from __future__ import annotations

import fnmatch
import glob
import gzip
import json
import os
import re
import time

from ..kb import vendor_node
from ..openpgp import WEAK_HASHES, clearsign_body, clearsign_signatures, parse_keyring
from ..util import (email_domain, host_of, iso, parse_deb822, reg_domain, run, safe_read, which)
from . import Status

NAME = "apt"
DESCRIPTION = "APT sources, signing keys, deb package provenance, pending updates, unattended-upgrades, Ubuntu Pro"

LISTS = "/var/lib/apt/lists"
GLOBAL_KEYRINGS = ["/etc/apt/trusted.gpg"] + sorted(
    glob.glob("/etc/apt/trusted.gpg.d/*.gpg") + glob.glob("/etc/apt/trusted.gpg.d/*.asc"))
KEYRING_DIRS = ["/usr/share/keyrings", "/etc/apt/keyrings"]
INSECURE_OPTS = ("allow-insecure", "allow-weak", "allow-downgrade-to-insecure")


def applicable(ctx):
    if not os.path.isdir("/etc/apt") or not which("dpkg-query"):
        return False, "not a dpkg/APT system"
    return True, ""


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------
def _split_opts(s):
    opts = {}
    for tok in s.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            k = k.rstrip("+-")
            opts[k.lower()] = [x for x in v.split(",") if x]
    return opts


def parse_one_line(text, path, ignored_file=False):
    out = []
    for ln, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        enabled = not ignored_file
        reason = "ignored-file" if ignored_file else None
        m = re.match(r"^#+\s*(deb(?:-src)?\s.*)$", line)
        if m:
            line, enabled, reason = m.group(1), False, reason or "commented-out"
        elif not line or line.startswith("#"):
            continue
        line = line.split(" #", 1)[0].strip()
        m = re.match(r"^(deb|deb-src)\s+(?:\[([^\]]*)\]\s+)?(\S+)\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        typ, optstr, uri, suite, comps = m.groups()
        out.append({
            "file": path, "line": ln, "format": "one-line", "type": typ, "uri": uri,
            "suite": suite, "components": comps.split(), "options": _split_opts(optstr or ""),
            "enabled": enabled, "disabled_reason": reason, "inline_key": None,
        })
    return out


def parse_deb822_sources(text, path, ignored_file=False):
    out = []
    # deb822 sources may contain an inline key in Signed-By (multi-line field)
    for st in parse_deb822(text):
        lower = {k.lower(): v for k, v in st.items()}
        if "uris" not in lower:
            continue
        enabled = lower.get("enabled", "yes").strip().lower() not in ("no", "false", "0")
        reason = None if enabled else "Enabled: no"
        if ignored_file:
            enabled, reason = False, "ignored-file"
        opts = {}
        for k, v in lower.items():
            if k in ("types", "uris", "suites", "components", "enabled", "signed-by"):
                continue
            opts[k] = [x for x in re.split(r"[\s,]+", v) if x]
        sb = lower.get("signed-by", "")
        inline = None
        if "BEGIN PGP PUBLIC KEY BLOCK" in sb:
            inline = sb.replace("\n\n", "\n")
            # restore armor blank line after header
            inline = re.sub(r"(-----BEGIN PGP PUBLIC KEY BLOCK-----\n)", r"\1\n", inline, count=1)
            opts["signed-by"] = ["<inline key>"]
        elif sb:
            opts["signed-by"] = sb.split()
        for typ in lower.get("types", "deb").split():
            for uri in lower["uris"].split():
                for suite in lower.get("suites", "").split():
                    out.append({
                        "file": path, "line": None, "format": "deb822", "type": typ, "uri": uri,
                        "suite": suite, "components": lower.get("components", "").split(),
                        "options": opts, "enabled": enabled, "disabled_reason": reason,
                        "inline_key": inline,
                    })
    return out


def parse_all_sources(root="/etc/apt"):
    entries = []
    main = os.path.join(root, "sources.list")
    if os.path.isfile(main):
        entries += parse_one_line(safe_read(main), main)
    d = os.path.join(root, "sources.list.d")
    for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        path = os.path.join(d, fn)
        if not os.path.isfile(path):
            continue
        txt = safe_read(path)
        if fn.endswith(".list"):
            entries += parse_one_line(txt, path)
        elif fn.endswith(".sources"):
            entries += parse_deb822_sources(txt, path)
        else:
            # APT ignores these (.disabled, .save, .distUpgrade, .dpkg-old ...)
            if txt and ("URIs:" in txt or "URIS:" in txt.upper()):
                entries += parse_deb822_sources(txt, path, ignored_file=True)
            else:
                entries += parse_one_line(txt, path, ignored_file=True)
    return [e for e in entries if e["type"] == "deb"]


def source_id(e):
    return "source:apt:%s|%s" % (e["uri"].rstrip("/"), e["suite"])


def uri_to_filename(uri):
    """Re-implementation of apt's URItoFileName()."""
    u = re.sub(r"^[a-zA-Z0-9+.-]+:(//)?", "", uri)
    first, sep, rest = u.partition("/")
    if "@" in first:
        first = first.split("@", 1)[1]
    u = first + sep + rest
    bad = '\\|{}[]<>"^~_=!@#$%^&*'
    q = "".join("%%%02x" % ord(c) if (c in bad or ord(c) <= 0x20 or ord(c) >= 0x7F) else c for c in u)
    return q.replace("/", "_")


def list_prefix(e):
    uri = e["uri"] if e["uri"].endswith("/") else e["uri"] + "/"
    if e["suite"].endswith("/"):  # flat repository
        path = uri + ("" if e["suite"] == "./" else e["suite"])
    else:
        path = uri + "dists/" + e["suite"] + "/"
    return uri_to_filename(path)


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------
class KeyStore:
    def __init__(self):
        self.by_file = {}
        self.fpr_index = {}  # any (sub)key fpr / long keyid -> primary fpr
        self.keys = {}       # primary fpr -> key dict (+ files)

    def load(self, path, data=None):
        if path in self.by_file:
            return self.by_file[path]
        if data is None:
            data = safe_read(path, binary=True)
        keys = parse_keyring(data) if data else []
        fprs = []
        for k in keys:
            fpr = k.get("fingerprint")
            if not fpr:
                continue
            fprs.append(fpr)
            cur = self.keys.setdefault(fpr, dict(k, files=[]))
            if path not in cur["files"]:
                cur["files"].append(path)
            for kk in [k] + k.get("subkeys", []):
                if kk.get("fingerprint"):
                    self.fpr_index[kk["fingerprint"]] = fpr
                    self.fpr_index[kk["keyid"]] = fpr
        self.by_file[path] = fprs
        return fprs

    def resolve(self, fpr_or_keyid):
        if not fpr_or_keyid:
            return None
        x = fpr_or_keyid.upper()
        return self.fpr_index.get(x) or self.fpr_index.get(x[-16:])


def _uid_domain(uids):
    for u in uids or []:
        d = email_domain(u)
        if d:
            return d
    return None


# ---------------------------------------------------------------------------
# release metadata
# ---------------------------------------------------------------------------
def release_info(prefix):
    for name in ("InRelease", "Release"):
        path = os.path.join(LISTS, prefix + name)
        txt = safe_read(path, 2 * 1024 * 1024)
        if txt is None:
            continue
        sigs = clearsign_signatures(txt) if name == "InRelease" else []
        if name == "Release":
            gpg = safe_read(path + ".gpg", binary=True)
            if gpg:
                from ..openpgp import packets, parse_signature, dearmor
                for blob in dearmor(gpg):
                    for tag, body in packets(blob):
                        if tag == 2:
                            s = parse_signature(body)
                            if s:
                                sigs.append(s)
        st = parse_deb822(clearsign_body(txt))
        fields = st[0] if st else {}
        hashes = [h for h in ("MD5Sum", "SHA1", "SHA256", "SHA512") if h in fields]
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = None
        return {
            "file": path,
            "fetched": mtime,
            "origin": fields.get("Origin"),
            "label": fields.get("Label"),
            "suite": fields.get("Suite"),
            "codename": fields.get("Codename"),
            "version": fields.get("Version"),
            "date": fields.get("Date"),
            "valid_until": fields.get("Valid-Until"),
            "acquire_by_hash": fields.get("Acquire-By-Hash"),
            "signed_by_field": fields.get("Signed-By"),
            "index_hashes": hashes,
            "signatures": [{"issuer": s.get("issuer_fpr") or s.get("issuer_keyid"), "hash": s.get("hash"),
                            "algo": s.get("pubalgo"), "created": iso(s.get("created"))} for s in sigs],
        }
    return None


# ---------------------------------------------------------------------------
# installed packages & provenance
# ---------------------------------------------------------------------------
DPKG_FMT = ("${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\t"
            "${db:Status-Abbrev}\t${Maintainer}\t${Section}\t${Homepage}\t${Installed-Size}\t${Essential}\n")


def installed_packages():
    r = run(["dpkg-query", "-W", "-f", DPKG_FMT], timeout=120)
    pkgs = {}
    for line in r.out.splitlines():
        p = line.split("\t")
        if len(p) < 11:
            continue
        name, arch, ver, sname, sver, status, maint, section, home, size, ess = p[:11]
        if not status.startswith(("ii", "hi", "iU", "iF", "hU", "hF")):
            continue
        pkgs[(name, arch)] = {
            "name": name, "arch": arch, "version": ver, "source_pkg": sname or name,
            "source_version": sver or ver, "status": status.strip(), "held": status.startswith("h"),
            "maintainer": maint, "section": section, "homepage": home or None,
            "installed_kb": int(size) if size.isdigit() else None, "essential": ess == "yes",
        }
    auto = set()
    for st in parse_deb822(safe_read("/var/lib/apt/extended_states", 32 * 1024 * 1024) or ""):
        if st.get("Auto-Installed") == "1":
            auto.add((st.get("Package"), st.get("Architecture")))
    for k, p in pkgs.items():
        p["manual"] = k not in auto
    return pkgs


def provenance_apt_pkg(pkgs, prefix_to_sid):
    """Use python3-apt (fast, exact). Returns False if unavailable."""
    try:
        import apt_pkg  # noqa
    except ImportError:
        return False
    if os.environ.get("SECDEPMAP_NO_APT_PKG"):
        return False
    apt_pkg.init()
    cache = apt_pkg.Cache(None)

    def sid_for(filename):
        base = os.path.basename(filename or "")
        for pre, sid in prefix_to_sid:
            if base.startswith(pre):
                return sid
        return None

    for (name, arch), p in pkgs.items():
        try:
            ap = cache[name, arch]
        except (KeyError, TypeError):
            try:
                ap = cache[name]
            except KeyError:
                continue
        cur = ap.current_ver
        inst, chans, comps = set(), set(), set()
        for ver in ap.version_list:
            for pf, _ in ver.file_list:
                if pf.not_source or pf.filename == "/var/lib/dpkg/status":
                    continue
                sid = sid_for(pf.filename)
                if not sid:
                    continue
                chans.add(sid)
                if cur is not None and ver.ver_str == cur.ver_str:
                    inst.add(sid)
                    if pf.component:
                        comps.add(pf.component)
        p["installed_in"] = sorted(inst)
        p["channels"] = sorted(chans)
        p["components"] = sorted(comps)
    return True


def provenance_fallback(pkgs, prefix_to_sid):
    """Parse Packages indexes directly (no python3-apt)."""
    names = {}
    for (n, a), p in pkgs.items():
        names.setdefault(n, []).append(p)
        p.setdefault("installed_in", [])
        p.setdefault("channels", [])
        p.setdefault("components", [])
    for fn in sorted(os.listdir(LISTS)) if os.path.isdir(LISTS) else []:
        if not re.search(r"_Packages(\.gz)?$", fn):
            continue
        sid, pre = None, None
        for pr, s in prefix_to_sid:
            if fn.startswith(pr):
                sid, pre = s, pr
                break
        if not sid:
            continue
        comp = fn[len(pre):].split("_binary-")[0].replace("_", "/") if "_binary-" in fn else None
        path = os.path.join(LISTS, fn)
        try:
            fh = gzip.open(path, "rt", errors="replace") if fn.endswith(".gz") else open(path, "r", errors="replace")
        except OSError:
            continue
        with fh:
            name = ver = arch = None
            for line in fh:
                if line.startswith("Package: "):
                    name = line[9:].strip()
                elif line.startswith("Version: "):
                    ver = line[9:].strip()
                elif line.startswith("Architecture: "):
                    arch = line[14:].strip()
                elif line == "\n":
                    if name in names:
                        for p in names[name]:
                            if arch in (p["arch"], "all") or p["arch"] == "all":
                                if sid not in p["channels"]:
                                    p["channels"].append(sid)
                                if ver == p["version"] and sid not in p["installed_in"]:
                                    p["installed_in"].append(sid)
                                    if comp and comp not in p["components"]:
                                        p["components"].append(comp)
                    name = ver = arch = None
    return True


UPG_RE = re.compile(r"^Inst (\S+) (?:\[([^\]]+)\] )?\((\S+) (.+?) \[([^\]]+)\]\)")


def pending_upgrades():
    r = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "APT::Get::Show-User-Simulation-Note=false",
             "dist-upgrade"], timeout=180)
    if r.missing or r.timeout:
        return None, "apt-get unavailable" if r.missing else "apt-get timed out"
    ups, phased = [], 0
    in_phase = False
    for line in r.out.splitlines():
        if "deferred due to phasing" in line:
            in_phase = True
            continue
        if in_phase:
            if line.startswith("  "):
                phased += len(line.split())
                continue
            in_phase = False
        m = UPG_RE.match(line)
        if not m:
            continue
        name, old, new, origins, arch = m.groups()
        ups.append({"name": name, "arch": arch, "from": old, "to": new, "origins": origins,
                    "security": bool(re.search(r"-security|Debian-Security|security", origins, re.I))})
    return {"upgrades": ups, "phased_deferred": phased}, None


# ---------------------------------------------------------------------------
# unattended-upgrades
# ---------------------------------------------------------------------------
def apt_config():
    r = run(["apt-config", "dump"], timeout=30)
    scalars, lists = {}, {}
    for line in r.out.splitlines():
        m = re.match(r'^(\S+?)(::)? "(.*)";$', line)
        if not m:
            continue
        k, is_list, v = m.groups()
        if is_list:
            lists.setdefault(k, []).append(v)
        else:
            scalars[k] = v
    return scalars, lists


def uu_coverage(scalars, lists, rel, distro_id, codename):
    """Does unattended-upgrades' policy allow this source's Release?"""
    if not rel:
        return False

    def sub(s):
        return s.replace("${distro_id}", distro_id).replace("${distro_codename}", codename)

    for item in lists.get("Unattended-Upgrade::Allowed-Origins", []):
        item = sub(item)
        if ":" in item:
            o, a = item.rsplit(":", 1)
            if fnmatch.fnmatchcase(rel.get("origin") or "", o) and \
                    (fnmatch.fnmatchcase(rel.get("suite") or "", a) or fnmatch.fnmatchcase(rel.get("codename") or "", a)):
                return True
    keymap = {"o": "origin", "origin": "origin", "l": "label", "label": "label", "a": "suite",
              "archive": "suite", "suite": "suite", "n": "codename", "codename": "codename"}
    for item in lists.get("Unattended-Upgrade::Origins-Pattern", []):
        item = sub(item)
        ok = True
        for cond in re.split(r"(?<!\\),", item):
            if "=" not in cond:
                continue
            k, v = cond.split("=", 1)
            field = keymap.get(k.strip().lower())
            if not field:
                continue  # site=, c= ... treat as match-anything (conservative)
            if not fnmatch.fnmatchcase(rel.get(field) or "", v.replace("\\,", ",")):
                ok = False
                break
        if ok:
            return True
    return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    os_vendor = ctx.shared.get("os_vendor")
    osr = ctx.shared.get("os_release", {})
    distro_id = osr.get("NAME", "").split()[0] if osr.get("NAME") else osr.get("ID", "").capitalize()
    codename = osr.get("VERSION_CODENAME", "")

    entries = parse_all_sources()
    keystore = KeyStore()
    for kr in GLOBAL_KEYRINGS:
        if os.path.exists(kr):
            keystore.load(kr)

    # merge entries that refer to the same uri+suite
    sources = {}
    for e in entries:
        sid = source_id(e)
        cur = sources.get(sid)
        if cur is None:
            sources[sid] = dict(e, components=list(e["components"]), files=[e["file"]])
        else:
            cur["components"] = sorted(set(cur["components"]) | set(e["components"]))
            if e["file"] not in cur["files"]:
                cur["files"].append(e["file"])
            if e["enabled"] and not cur["enabled"]:
                cur.update(enabled=True, disabled_reason=None, options=e["options"], inline_key=e["inline_key"])

    prefix_to_sid = []
    plaintext = []
    scfg_scalars, scfg_lists = apt_config()
    referenced_keyrings = set()
    newest_fetch = 0

    for sid, e in sources.items():
        e["prefix"] = list_prefix(e)
        rel = release_info(e["prefix"]) if e["enabled"] else None
        e["release"] = rel
        if e["enabled"]:
            prefix_to_sid.append((e["prefix"], sid))
        host = host_of(e["uri"])
        scheme = e["uri"].split(":", 1)[0].lower()
        opts = e["options"]
        # --- trust anchors
        sb = opts.get("signed-by", [])
        anchors, scope = [], "scoped"
        if e["inline_key"]:
            anchors = keystore.load("inline:" + sid, e["inline_key"].encode())
        elif sb:
            for item in sb:
                if item.startswith("/"):
                    anchors += keystore.load(item)
                    if e["enabled"]:
                        referenced_keyrings.add(item)
                else:  # fingerprint form
                    fp = keystore.resolve(item.rstrip("!"))
                    if fp:
                        anchors.append(fp)
        else:
            scope = "global"
            for kr in GLOBAL_KEYRINGS:
                anchors += keystore.by_file.get(kr, [])
        if opts.get("trusted", [""])[0].lower() == "yes":
            scope = "trusted=yes (no verification)"
        # actual signer of the Release file
        signers = []
        for sig in (rel or {}).get("signatures", []):
            fp = keystore.resolve(sig["issuer"])
            signers.append({"fpr": fp or sig["issuer"], "hash": sig["hash"], "known": bool(fp)})

        # --- vendor attribution
        vid = kb.match_any([("apt_origin", (rel or {}).get("origin")), ("apt_label", (rel or {}).get("label"))]) \
            or kb.vendor_for_domain(host)
        vnode = vendor_node(g, kb, vid, fallback_name=(rel or {}).get("origin") or reg_domain(host),
                            fallback_domain=reg_domain(host))
        official = bool(os_vendor and vnode == os_vendor)

        list_files = []
        if e["enabled"] and os.path.isdir(LISTS):
            list_files = [f for f in os.listdir(LISTS) if f.startswith(e["prefix"])]
        fetched = (rel or {}).get("fetched")
        if fetched:
            newest_fetch = max(newest_fetch, fetched)
        e["uu_covered"] = uu_coverage(scfg_scalars, scfg_lists, rel, distro_id, codename) if e["enabled"] else False

        g.node(sid, "source", "%s %s" % (host or e["uri"], e["suite"]),
               ecosystem="deb", kind="apt-repository", uri=e["uri"], suite=e["suite"],
               components=e["components"], enabled=e["enabled"], disabled_reason=e["disabled_reason"],
               files=e["files"], transport=scheme, signed_by=sb or None, trust_scope=scope,
               options={k: v for k, v in opts.items() if k != "signed-by"} or None,
               release={k: v for k, v in (rel or {}).items() if k not in ("signatures",)} or None,
               release_signers=signers or None, official=official,
               unattended_upgrades=e["uu_covered"], list_files=len(list_files))
        g.edge(sid, vnode, "operated_by")
        for fp in sorted(set(anchors)):
            g.edge(sid, "anchor:pgp:" + fp, "trusts", used=any(x["fpr"] == fp for x in signers) or None)
        for sg in signers:
            if sg["known"]:
                g.edge(sid, "anchor:pgp:" + sg["fpr"], "signed_by")

        # --- per-source findings
        label = "%s (%s)" % (e["uri"], e["suite"])
        if e["enabled"]:
            if scope.startswith("trusted=yes"):
                g.finding("apt.source.trusted-yes:" + sid, "high",
                          "APT signature verification disabled for %s" % label,
                          "The source sets [trusted=yes]; anyone able to tamper with the network path or mirror can "
                          "serve arbitrary packages that will be installed as root.",
                          nodes=[sid], evidence={"file": e["files"]},
                          remediation="Remove trusted=yes and configure Signed-By with the vendor's key.",
                          category="supply-chain")
            bad = [o for o in INSECURE_OPTS if opts.get(o, ["no"])[0].lower() in ("yes", "true", "1")]
            if bad:
                g.finding("apt.source.insecure-options:" + sid, "high",
                          "Insecure APT options on %s" % label, "Options weaken repository verification: %s" % ", ".join(bad),
                          nodes=[sid], remediation="Remove %s from the source definition." % ", ".join(bad),
                          category="supply-chain")
            if scope == "global" and not official:
                g.finding("apt.source.no-signed-by:" + sid, "medium",
                          "Third-party source trusts every global APT key: %s" % label,
                          "Without Signed-By, packages from this repository may be signed by ANY key in "
                          "/etc/apt/trusted.gpg(.d) and, conversely, its key can sign packages for other repositories.",
                          nodes=[sid], remediation="Move the vendor key to /etc/apt/keyrings/ and add Signed-By=.",
                          refs=["https://wiki.debian.org/DebianRepository/UseThirdParty"], category="supply-chain")
            if scheme in ("http", "ftp"):
                plaintext.append((sid, label, (rel or {}).get("valid_until")))
            if not rel:
                g.finding("apt.source.no-metadata:" + sid, "medium",
                          "Enabled source has no downloaded metadata: %s" % label,
                          "No InRelease/Release in %s - 'apt update' may be failing for this source, so its packages "
                          "receive no updates." % LISTS, nodes=[sid],
                          remediation="Run 'sudo apt update' and check for errors.", category="patching")
            else:
                for sg in signers:
                    if sg["hash"] in WEAK_HASHES:
                        g.finding("apt.source.weak-signature:" + sid, "high",
                                  "Repository signed with weak hash %s: %s" % (sg["hash"], label),
                                  "Release signatures using %s are forgeable or deprecated." % sg["hash"], nodes=[sid],
                                  category="supply-chain")
                if rel["index_hashes"] and not set(rel["index_hashes"]) & {"SHA256", "SHA512"}:
                    g.finding("apt.source.weak-index-hashes:" + sid, "medium",
                              "Repository indexes only use %s: %s" % ("/".join(rel["index_hashes"]), label),
                              nodes=[sid], category="supply-chain")
        if e["inline_key"] is None and sb:
            for item in sb:
                if item.startswith("/") and not os.path.exists(item):
                    g.finding("apt.source.missing-keyring:" + sid, "medium" if e["enabled"] else "info",
                              "Signed-By keyring missing: %s" % item, nodes=[sid], category="supply-chain")

    if plaintext:
        unbounded = [x for x in plaintext if not x[2]]
        g.finding("apt.sources.plaintext", "low" if unbounded else "info",
                  "%d APT source(s) fetched over plain HTTP" % len(plaintext),
                  "Packages are still verified through the signed Release file, but an on-path attacker can see what you "
                  "install and replay old signed metadata to withhold security updates.%s" % (
                      " %d of them have no Valid-Until, so that freeze window is unbounded." % len(unbounded) if unbounded else ""),
                  nodes=[x[0] for x in plaintext], evidence={"sources": [x[1] for x in plaintext]},
                  remediation="Switch the mirror URIs to https:// (Ubuntu and Debian mirrors support it).", category="transport")

    # --- key nodes ------------------------------------------------------------
    owners = ctx.resolve_owners([f for k in keystore.keys.values() for f in k["files"] if f.startswith("/")])
    now = time.time()
    for fpr, k in keystore.keys.items():
        aid = "anchor:pgp:" + fpr
        dom = _uid_domain(k["uids"])
        global_files = [f for f in k["files"] if f in GLOBAL_KEYRINGS]
        g.node(aid, "anchor", (k["uids"][0] if k["uids"] else fpr[-16:]),
               kind="openpgp-key", fingerprint=fpr, algo=k["algo"], bits=k["bits"], curve=k.get("curve"),
               created=iso(k["created"]), expires=iso(k["expires"]), revoked=k["revoked"],
               uids=k["uids"], files=k["files"], scope="global" if global_files else "scoped",
               owned_by_package={f: owners.get(f) for f in k["files"] if f in owners} or None,
               subkeys=[{"fingerprint": sk["fingerprint"], "algo": sk["algo"], "bits": sk["bits"],
                         "expires": iso(sk["expires"])} for sk in k["subkeys"]] or None)
        kv = kb.match("key_uid_domain", dom) or kb.vendor_for_domain(dom) if dom else None
        g.edge(aid, vendor_node(g, kb, kv, fallback_domain=reg_domain(dom) if dom else None,
                                fallback_name=None if dom else "unknown key owner"), "issued_by")
        in_use = any(e["dst"] == aid and e["rel"] in ("trusts", "signed_by") and g.nodes[e["src"]]["attrs"].get("enabled")
                     for e in g.edges)
        weak = (k["algo"] in ("RSA", "RSA-S", "DSA") and (k["bits"] or 0) < 2048) or k["algo"] == "DSA"
        if weak and (in_use or global_files):
            g.finding("apt.key.weak:" + fpr, "high", "Weak APT trust anchor %s %s-%s" % (fpr[-16:], k["algo"], k["bits"]),
                      "Keys below 2048-bit RSA or DSA keys are not considered safe.", nodes=[aid], category="supply-chain")
        if k["expires"] and k["expires"] < now and in_use:
            g.finding("apt.key.expired:" + fpr, "high", "Expired signing key still in use: %s" % (k["uids"] or [fpr])[0],
                      "Sources depending only on this key fail to update.", nodes=[aid], category="patching")
        elif k["expires"] and k["expires"] - now < 60 * 86400 and in_use:
            g.finding("apt.key.expiring:" + fpr, "low", "Signing key expires soon (%s): %s" % (iso(k["expires"])[:10], (k["uids"] or [fpr])[0]),
                      nodes=[aid], category="patching")
        if k["revoked"] and in_use:
            g.finding("apt.key.revoked:" + fpr, "high", "Revoked key trusted by APT: %s" % fpr, nodes=[aid], category="supply-chain")
        if global_files:
            distro = all((owners.get(f) or "").endswith("-keyring") or (owners.get(f) or "") in ("ubuntu-keyring", "debian-archive-keyring")
                         for f in global_files)
            if not distro:
                g.finding("apt.key.global-trust:" + fpr, "medium",
                          "Non-distribution key trusted globally by APT: %s" % (k["uids"] or [fpr])[0],
                          "Keys in %s can sign metadata for ANY repository, including impersonating the "
                          "distribution archive." % ", ".join(global_files), nodes=[aid],
                          remediation="Move the key to /etc/apt/keyrings/ and reference it with Signed-By.",
                          category="supply-chain")

    # unreferenced keyrings (residue of removed/disabled repos)
    leftover_by_vendor = {}
    for d in KEYRING_DIRS:
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            path = os.path.join(d, fn)
            if path in referenced_keyrings or not os.path.isfile(path):
                continue
            own = ctx.resolve_owners([path]).get(path)
            if own:
                continue  # shipped by a package (distro keyrings, *-keyring packages)
            fprs = keystore.load(path)
            for fp in fprs:
                aid = "anchor:pgp:" + fp
                if not g.has(aid):
                    k = keystore.keys[fp]
                    g.node(aid, "anchor", (k["uids"][0] if k["uids"] else fp[-16:]), kind="openpgp-key",
                           fingerprint=fp, algo=k["algo"], bits=k["bits"], created=iso(k["created"]),
                           expires=iso(k["expires"]), uids=k["uids"], files=k["files"], scope="unreferenced")
                    dom = _uid_domain(k["uids"])
                    kv = (kb.match("key_uid_domain", dom) or kb.vendor_for_domain(dom)) if dom else None
                    g.edge(aid, vendor_node(g, kb, kv, fallback_domain=reg_domain(dom) if dom else None), "issued_by")
            for fp in fprs:
                for e2 in g.out_edges("anchor:pgp:" + fp, "issued_by"):
                    leftover_by_vendor.setdefault(e2["dst"], set()).add(path)
            g.finding("apt.keyring.unreferenced:" + path, "low",
                      "Leftover APT keyring not used by any enabled source: %s" % path,
                      "Manually installed trust material from a removed or disabled repository. Harmless while unreferenced, "
                      "but it widens what an attacker can re-enable and hides provenance.",
                      nodes=["anchor:pgp:" + fp for fp in fprs], remediation="Delete it if the repository is no longer needed.",
                      category="hygiene")

    # --- packages ---------------------------------------------------------------
    pkgs = installed_packages()
    used_apt_pkg = provenance_apt_pkg(pkgs, prefix_to_sid)
    if not used_apt_pkg:
        s.note("python3-apt not available; parsed Packages indexes directly")
        provenance_fallback(pkgs, prefix_to_sid)

    disabled = {sid: e for sid, e in sources.items() if not e["enabled"]}
    local_sid = "source:apt:local"
    no_source, obsolete, from_disabled, held = [], [], {}, []
    removed_repo, distro_leftover = {}, []
    for (name, arch), p in sorted(pkgs.items()):
        pid = "pkg:deb:%s:%s" % (name, arch)
        cls, likely, reason = None, None, None
        doms = {reg_domain(email_domain(p["maintainer"])), reg_domain(host_of(p["homepage"] or ""))} - {None}
        vids = {kb.match("maintainer_domain", d) or kb.vendor_for_domain(d) for d in doms} - {None}
        pub_vendor = sorted(vids)[0] if vids else None
        if p["installed_in"]:
            off = any(g.nodes[x]["attrs"].get("official") for x in p["installed_in"])
            cls = "official" if off else "third-party"
        elif p["channels"]:
            cls = "obsolete"   # name known, installed version not offered any more
        else:
            cls = "no-source"
            # was it installed from a now-disabled repo? match maintainer/homepage domain to source host
            for dsid, de in disabled.items():
                h = reg_domain(host_of(de["uri"]))
                dv = kb.vendor_for_domain(host_of(de["uri"]))
                if dv and os_vendor and "vendor:" + dv == os_vendor:
                    continue  # don't attribute leftovers to a disabled distro archive
                if (h and h in doms) or (dv and dv in vids):
                    likely = dsid
                    break
            if likely:
                reason = "disabled-source"
            elif pub_vendor and "vendor:" + pub_vendor in leftover_by_vendor:
                reason = "removed-repository"
                removed_repo.setdefault("vendor:" + pub_vendor, []).append(name)
            elif pub_vendor and os_vendor and "vendor:" + pub_vendor == os_vendor:
                reason = "distro-leftover"
                distro_leftover.append(name)
            else:
                reason = "manual"
        p["origin_class"] = cls
        p["likely_source"] = likely
        p["no_source_reason"] = reason
        g.node(pid, "package", name, ecosystem="deb", version=p["version"], arch=arch,
               source_pkg=p["source_pkg"], source_version=p["source_version"], maintainer=p["maintainer"],
               section=p["section"], homepage=p["homepage"], manual=p["manual"], held=p["held"] or None,
               essential=p["essential"] or None, origin_class=cls, components=p["components"] or None,
               channels=p["channels"] or None, likely_source=likely, no_source_reason=reason)
        for sid in p["installed_in"]:
            g.edge(pid, sid, "from")
        if pub_vendor and cls != "official" and ("vendor:" + pub_vendor) != os_vendor:
            g.edge(pid, vendor_node(g, kb, pub_vendor), "published_by")
        elif cls == "no-source" and not pub_vendor and doms and reason == "manual":
            d0 = sorted(doms)[0]
            g.edge(pid, vendor_node(g, kb, None, fallback_domain=d0, fallback_name=d0), "published_by")
        if not p["installed_in"]:
            if likely:
                g.edge(pid, likely, "from", likely=True)
                from_disabled.setdefault(likely, []).append(name)
            elif p["channels"]:
                for sid in p["channels"]:
                    g.edge(pid, sid, "from", outdated=True)
                obsolete.append(name)
            else:
                g.edge(pid, local_sid, "from")
                if reason == "manual":
                    no_source.append(name)
        if p["held"]:
            held.append(name)

    if any(p["origin_class"] == "no-source" and not p["likely_source"] for p in pkgs.values()):
        g.node(local_sid, "source", "Local .deb files / removed repositories", ecosystem="deb", kind="local",
               enabled=True, trust_scope="none", official=False)
        g.edge(local_sid, "vendor:manual", "operated_by")
        g.node("vendor:manual", "vendor", "Manual install (no supplier channel)", kb=False, pseudo=True)
    if no_source:
        g.finding("apt.packages.no-source", "medium",
                  "%d deb package(s) installed from local .deb files - no update channel" % len(no_source),
                  "Nothing will deliver security updates for them; you depend on the vendor's own updater (if any) or "
                  "on noticing new releases yourself.",
                  nodes=["pkg:deb:%s:%s" % k for k in pkgs if pkgs[k].get("no_source_reason") == "manual"][:500],
                  evidence={"packages": sorted(no_source)},
                  remediation="Switch to the vendor's APT repository / a snap or flatpak with auto-updates, or remove them.",
                  category="patching")
    for vnode_id, names in removed_repo.items():
        g.finding("apt.packages.removed-repository:" + vnode_id, "high",
                  "Packages from a REMOVED repository get no updates: %s" % ", ".join(sorted(names)[:6]),
                  "%d package(s) by %s are installed, the vendor's signing key is still on disk (%s), but no source "
                  "for it is configured any more - they are frozen at their current version." % (
                      len(names), g.nodes[vnode_id]["label"], ", ".join(sorted(leftover_by_vendor[vnode_id]))),
                  nodes=[vnode_id] + ["pkg:deb:%s:%s" % k for k in pkgs if pkgs[k]["name"] in names],
                  evidence={"packages": sorted(names), "keyrings": sorted(leftover_by_vendor[vnode_id])},
                  remediation="Re-add the vendor repository with Signed-By, or uninstall the packages.",
                  category="patching")
    if distro_leftover:
        g.finding("apt.packages.distro-leftover", "low",
                  "%d package(s) from previous distribution releases no longer receive updates" % len(distro_leftover),
                  "Removed from the current release but still installed (often libraries kept after an upgrade).",
                  nodes=["pkg:deb:%s:%s" % k for k in pkgs if pkgs[k]["name"] in distro_leftover],
                  evidence={"packages": sorted(distro_leftover)},
                  remediation="Review with 'apt list ?obsolete' and remove what is unused (sudo apt autoremove / apt purge).",
                  category="hygiene")
    for dsid, names in from_disabled.items():
        de = sources[dsid]
        g.finding("apt.source.disabled-with-packages:" + dsid, "high",
                  "Packages from a DISABLED source get no updates: %s" % ", ".join(sorted(names)[:6]),
                  "%s is disabled (%s) but %d installed package(s) appear to come from it. They are frozen at "
                  "their current version." % (de["uri"], de["disabled_reason"], len(names)),
                  nodes=[dsid] + ["pkg:deb:%s:%s" % k for k in pkgs if pkgs[k]["name"] in names],
                  evidence={"packages": sorted(names), "file": de["files"]},
                  remediation="Re-enable the source (and fix its key) or uninstall the packages.",
                  category="patching")
    if obsolete:
        g.finding("apt.packages.obsolete", "low",
                  "%d deb packages are at a version no configured repository offers" % len(obsolete),
                  "Typically leftovers from a previous release upgrade or a downgrade/pin.",
                  evidence={"packages": sorted(obsolete)[:300]}, category="hygiene")
    if held:
        g.finding("apt.packages.held", "medium", "%d package(s) on hold do not receive updates" % len(held),
                  evidence={"packages": sorted(held)}, remediation="apt-mark unhold <pkg> after review.",
                  category="patching")

    # --- updates ------------------------------------------------------------------
    up, err = pending_upgrades()
    if err:
        s.partial(err)
    else:
        sec = [u for u in up["upgrades"] if u["security"]]
        for u in up["upgrades"]:
            pid = "pkg:deb:%s:%s" % (u["name"], u["arch"])
            if g.has(pid):
                g.nodes[pid]["attrs"]["update"] = {"to": u["to"], "origins": u["origins"], "security": u["security"]}
        if sec:
            g.finding("apt.updates.security-pending", "high",
                      "%d security update(s) available but not installed" % len(sec),
                      evidence={"packages": ["%s %s -> %s" % (u["name"], u["from"], u["to"]) for u in sec]},
                      nodes=["pkg:deb:%s:%s" % (u["name"], u["arch"]) for u in sec],
                      remediation="sudo apt update && sudo apt upgrade", category="patching")
        other = [u for u in up["upgrades"] if not u["security"]]
        if other:
            g.finding("apt.updates.pending", "low", "%d non-security update(s) pending" % len(other),
                      evidence={"packages": ["%s %s -> %s (%s)" % (u["name"], u["from"], u["to"], u["origins"]) for u in other]},
                      nodes=["pkg:deb:%s:%s" % (u["name"], u["arch"]) for u in other], category="patching")
        s.stats["upgrades"] = len(up["upgrades"])
        s.stats["security_upgrades"] = len(sec)
        s.stats["phased_deferred"] = up["phased_deferred"]

    last_update = None
    for stamp in ("/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin"):
        if os.path.exists(stamp):
            last_update = os.path.getmtime(stamp)
            break
    last_update = last_update or newest_fetch or None
    s.stats["last_apt_update"] = iso(last_update)
    if last_update and time.time() - last_update > 7 * 86400:
        g.finding("apt.lists.stale", "medium", "APT metadata not refreshed for %d days" % ((time.time() - last_update) // 86400),
                  "Pending-update information is only as fresh as the last successful 'apt update'.", category="patching")

    # --- unattended upgrades -----------------------------------------------------
    uu_installed = any(p["name"] == "unattended-upgrades" for p in pkgs.values())
    uu_on = scfg_scalars.get("APT::Periodic::Unattended-Upgrade", "0") not in ("0", "", "false")
    covered = [sid for sid, e in sources.items() if e.get("uu_covered")]
    if g.has(ctx.host_id):
        g.nodes[ctx.host_id]["attrs"]["unattended_upgrades"] = {
            "installed": uu_installed, "enabled": uu_on,
            "allowed_origins": scfg_lists.get("Unattended-Upgrade::Allowed-Origins", []),
            "origins_pattern": scfg_lists.get("Unattended-Upgrade::Origins-Pattern", []),
            "covered_sources": covered,
        }
    if not (uu_installed and uu_on):
        g.finding("apt.unattended.disabled", "medium", "Automatic security updates are not enabled",
                  "unattended-upgrades is %s and APT::Periodic::Unattended-Upgrade=%s." %
                  ("installed" if uu_installed else "not installed", scfg_scalars.get("APT::Periodic::Unattended-Upgrade", "unset")),
                  remediation="sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
                  category="patching")
    else:
        third = {}
        for (name, arch), p in pkgs.items():
            if p["origin_class"] == "third-party" and not any(sources[x].get("uu_covered") for x in p["installed_in"]):
                for x in p["installed_in"]:
                    third.setdefault(x, []).append(name)
        if third:
            g.finding("apt.unattended.third-party-not-covered", "low",
                      "Third-party repositories are not covered by unattended-upgrades",
                      "%d package(s) from %d source(s) only update when someone runs apt manually." %
                      (sum(len(v) for v in third.values()), len(third)),
                      nodes=list(third), evidence={sid: sorted(v) for sid, v in third.items()},
                      remediation="Add their Origin to Unattended-Upgrade::Origins-Pattern if you trust the vendor's QA.",
                      category="patching")

    # --- Ubuntu Pro ---------------------------------------------------------------
    if which("pro") and ctx.shared.get("os_release", {}).get("ID") == "ubuntu":
        _ubuntu_pro(ctx, g, s, pkgs)

    by_class = {}
    for p in pkgs.values():
        by_class[p["origin_class"]] = by_class.get(p["origin_class"], 0) + 1
    s.stats.update(packages=len(pkgs), sources_enabled=sum(1 for e in sources.values() if e["enabled"]),
                   sources_disabled=len(disabled), keys=len(keystore.keys), by_origin_class=by_class,
                   provenance_backend="python3-apt" if used_apt_pkg else "index-parser")
    ctx.shared["deb_packages"] = pkgs
    ctx.shared["apt_sources"] = sources
    return s


def _ubuntu_pro(ctx, g, s, pkgs):
    st = run(["pro", "status", "--format", "json"], timeout=90)
    sec = run(["pro", "security-status", "--format", "json"], timeout=180)
    try:
        status = json.loads(st.out) if st.ok or st.out.strip().startswith("{") else {}
    except ValueError:
        status = {}
    try:
        secs = json.loads(sec.out) if sec.out.strip().startswith("{") else {}
    except ValueError:
        secs = {}
    if not status and not secs:
        s.partial("pro CLI present but returned no JSON")
        return
    attached = bool(status.get("attached"))
    services = {x.get("name"): x.get("status") for x in status.get("services", [])}
    summ = secs.get("summary", {})
    g.node(ctx.host_id, "host")["attrs"]["ubuntu_pro"] = {
        "attached": attached, "services": services,
        "summary": {k: v for k, v in summ.items() if k != "ua"},
    }
    pending = [p for p in secs.get("packages", []) if p.get("status") == "pending_attach"]
    if pending:
        names = sorted({p["package"] for p in pending})
        g.finding("ubuntu.pro.esm-fixes-unapplied", "high",
                  "%d security fix(es) published for installed packages but only available via Ubuntu Pro (ESM)" % len(pending),
                  "Canonical has released patched versions for these packages through Expanded Security Maintenance. "
                  "Without attaching Ubuntu Pro (free for personal use on a small number of machines) they stay vulnerable.",
                  nodes=["pkg:deb:%s:%s" % k for k in pkgs if pkgs[k]["name"] in names],
                  evidence={"packages": ["%s -> %s (%s)" % (p["package"], p.get("version"), p.get("service_name")) for p in pending]},
                  remediation="sudo pro attach <token>  (https://ubuntu.com/pro), then apt upgrade.",
                  refs=["https://ubuntu.com/pro"], category="patching")
        for p in pending:
            for k, v in pkgs.items():
                if v["name"] == p["package"]:
                    g.nodes["pkg:deb:%s:%s" % k]["attrs"]["esm_fix"] = p.get("version")
    if not attached and summ.get("num_universe_packages"):
        g.finding("ubuntu.universe.no-vendor-commitment", "info",
                  "%d installed packages come from universe/multiverse" % (summ.get("num_universe_packages", 0) + summ.get("num_multiverse_packages", 0)),
                  "Canonical's standard security maintenance covers main/restricted. Universe/multiverse fixes are "
                  "community best-effort unless Ubuntu Pro (ESM Apps) is attached.",
                  refs=["https://ubuntu.com/about/release-cycle"], category="vendor-coverage")
    if summ.get("reboot_required") == "yes":
        g.finding("ubuntu.reboot-required", "medium", "Reboot required to activate installed security updates",
                  category="patching")
