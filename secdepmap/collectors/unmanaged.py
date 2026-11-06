"""Software that no package manager owns: /opt, /usr/local, ~/.local/bin, AppImages.

Also checks that directories on root's PATH cannot be written by
unprivileged users (a classic local privilege escalation)."""

from __future__ import annotations

import os
import stat
import time

from ..kb import vendor_node
from ..util import iso, listdir, mode_issues, safe_read, sha256_file
from . import Status

NAME = "unmanaged"
DESCRIPTION = "Unpackaged software in /opt, /usr/local, ~/.local/bin and AppImages; PATH directory permissions"

ROOT_PATH_DIRS = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin"]


def applicable(ctx):
    return True, ""


def _src(g, kb, sid, label):
    if not g.has(sid):
        g.node(sid, "source", label, ecosystem="unmanaged", kind="manual", enabled=True,
               trust_scope="none (no signature verification, no update channel)")
        g.edge(sid, vendor_node(g, kb, None, fallback_name="Manual install"), "operated_by")
    return sid


def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    do_hash = ctx.options.get("hash", False)
    count = 0

    # ---- PATH directory permissions -----------------------------------------
    for d in ROOT_PATH_DIRS:
        if not os.path.isdir(d) or os.path.islink(d):
            continue
        issues = mode_issues(d)
        if issues:
            g.finding("path.writable:" + d, "high", "Directory on root's PATH is writable by non-root: %s" % d,
                      "Any program placed here can be executed by root (%s)." % ", ".join(issues),
                      evidence={"dir": d, "issues": issues}, remediation="chown root:root %s && chmod 755 %s" % (d, d),
                      category="access")

    # ---- /opt ------------------------------------------------------------------
    opt = [os.path.join("/opt", x) for x in listdir("/opt")]
    owners = ctx.resolve_owners(opt)
    for d in opt:
        own = owners.get(d)
        if own:
            for k, p in (ctx.shared.get("deb_packages") or {}).items():
                if p["name"] == own:
                    nid = "pkg:deb:%s:%s" % k
                    if g.has(nid):
                        g.nodes[nid]["attrs"].setdefault("install_paths", []).append(d)
            continue
        if not os.path.isdir(d):
            continue
        try:
            st = os.stat(d)
        except OSError:
            continue
        vid = kb.match("path", d)
        pid = "pkg:unmanaged:" + d
        g.node(pid, "package", os.path.basename(d), ecosystem="unmanaged", path=d, kind="directory",
               mtime=iso(st.st_mtime), owner_uid=st.st_uid, perm_issues=mode_issues(d) or None)
        g.edge(pid, _src(g, kb, "source:unmanaged:opt", "/opt (manually installed)"), "from")
        if vid:
            g.edge(pid, vendor_node(g, kb, vid), "published_by")
        count += 1

    # ---- /usr/local -------------------------------------------------------------
    npm_links = 0
    unmanaged_local = []
    for d in ("/usr/local/bin", "/usr/local/sbin"):
        entries = [os.path.join(d, x) for x in listdir(d)]
        owners = ctx.resolve_owners(entries)
        for p in entries:
            if owners.get(p):
                continue
            target = os.path.realpath(p)
            if "/node_modules/" in target:
                npm_links += 1
                continue
            try:
                st = os.lstat(p)
                tst = os.stat(p)
            except OSError:
                continue
            if not stat.S_ISREG(tst.st_mode):
                continue
            issues = mode_issues(p) + ([] if target == p else ["target: " + ", ".join(mode_issues(target))] if mode_issues(target) else [])
            vid = kb.match("path", p) or kb.match("path", target)
            pid = "pkg:unmanaged:" + p
            g.node(pid, "package", os.path.basename(p), ecosystem="unmanaged", path=p, target=target if target != p else None,
                   kind="binary", size=tst.st_size, mtime=iso(tst.st_mtime), owner_uid=tst.st_uid,
                   sha256=sha256_file(target, 512 * 1024 * 1024) if do_hash else None, perm_issues=issues or None,
                   elf=_is_elf(target))
            g.edge(pid, _src(g, kb, "source:unmanaged:usr-local", "/usr/local (manually installed)"), "from")
            if vid:
                g.edge(pid, vendor_node(g, kb, vid), "published_by")
            unmanaged_local.append(p)
            count += 1
            if issues:
                g.finding("unmanaged.perm:" + p, "high", "Executable in /usr/local is modifiable by non-root: %s" % p,
                          ", ".join(issues), nodes=[pid], category="access")
    if unmanaged_local:
        g.finding("unmanaged.usr-local", "medium",
                  "%d unpackaged program(s) in /usr/local: %s" % (len(unmanaged_local), ", ".join(os.path.basename(x) for x in unmanaged_local[:8])),
                  "Installed by script/tarball: no signature verification after install, no update channel, not covered by "
                  "any vendor advisory feed you are subscribed to via the package manager. They are on root's PATH.",
                  nodes=["pkg:unmanaged:" + p for p in unmanaged_local], evidence={"files": unmanaged_local},
                  remediation="Prefer a packaged/repo version, or track the vendor's releases and update manually.",
                  category="patching")

    # ---- ~/.local/bin and AppImages ---------------------------------------------
    eps = ctx.shared.get("pip_entrypoints", {})
    for u in ctx.users_to_scan():
        lb = os.path.join(u["home"], ".local/bin")
        unk = []
        for name in listdir(lb):
            p = os.path.join(lb, name)
            target = os.path.realpath(p)
            managed = None
            if name in eps:
                managed = eps[name]
            elif "/pipx/" in target or "/uv/tools/" in target:
                managed = "pipx/uv"
            elif "/node_modules/" in target:
                managed = "npm"
            else:
                vid = kb.match("path", target)
                if vid:
                    pid = "pkg:selfupdating:%s:%s" % (u["name"], name)
                    g.node(pid, "package", name, ecosystem="vendor-installer", path=p, target=target, user=u["name"],
                           kind="self-updating")
                    g.edge(pid, vendor_node(g, kb, vid), "published_by")
                    sid = "source:vendor-installer:" + vid
                    if not g.has(sid):
                        g.node(sid, "source", "%s installer/self-updater" % kb.vendors[vid].get("name", vid),
                               ecosystem="vendor-installer", kind="vendor-download", enabled=True,
                               trust_scope="vendor-controlled (verify their update signing)")
                        g.edge(sid, vendor_node(g, kb, vid), "operated_by")
                    g.edge(pid, sid, "from")
                    continue
                head = safe_read(p, 256) if os.path.isfile(p) else None
                if head and head.startswith("#!") and "python" in head.splitlines()[0]:
                    managed = "python-script (package not found)"
            if not managed and os.path.isfile(target):
                unk.append(name)
        if unk:
            sid = _src(g, kb, "source:unmanaged:home:" + u["name"], "~%s/.local/bin (manual)" % u["name"])
            for name in unk:
                p = os.path.join(lb, name)
                pid = "pkg:unmanaged:" + p
                g.node(pid, "package", name, ecosystem="unmanaged", path=p, user=u["name"], kind="binary",
                       elf=_is_elf(os.path.realpath(p)))
                g.edge(pid, sid, "from")
                count += 1
            g.finding("unmanaged.local-bin:" + u["name"], "low",
                      "%d unattributed executable(s) in ~%s/.local/bin" % (len(unk), u["name"]),
                      "Not owned by a package manager or a known vendor updater.", evidence={"files": unk},
                      category="hygiene")
        for d in ("Applications", ".local/bin", "Downloads", "bin", "opt"):
            for name in listdir(os.path.join(u["home"], d)):
                if name.lower().endswith(".appimage"):
                    p = os.path.join(u["home"], d, name)
                    pid = "pkg:appimage:" + p
                    try:
                        mt = os.stat(p).st_mtime
                    except OSError:
                        continue
                    g.node(pid, "package", name, ecosystem="appimage", path=p, user=u["name"], mtime=iso(mt),
                           age_days=int((time.time() - mt) / 86400))
                    g.edge(pid, _src(g, kb, "source:unmanaged:appimage", "AppImages (manual download)"), "from")
                    count += 1
    s.stats.update(unmanaged=count, npm_global_links=npm_links)
    return s


def _is_elf(path):
    b = safe_read(path, 4, binary=True)
    return (b == b"\x7fELF") if b else None
