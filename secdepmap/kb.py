"""Vendor knowledge base: maps observed identifiers to vendors and their
security channels (advisories, PSIRT, lifecycle, machine-readable feeds).

The KB is plain JSON so it can be extended without code changes. Files are
loaded in order and merged by vendor ``id`` (later files override fields):

1. ``<repo>/kb/*.json``           shipped defaults
2. ``/etc/secdepmap/kb.d/*.json``  site-local additions / overrides
3. ``--kb DIR`` or ``$SECDEPMAP_KB_PATH`` (colon separated)
"""

from __future__ import annotations

import json
import os

from .util import glob_match, reg_domain, safe_read

REPO_KB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kb")
SITE_KB = "/etc/secdepmap/kb.d"

MATCH_KINDS = (
    "apt_origin", "apt_label", "url_host", "snap_publisher", "flatpak_remote",
    "flatpak_app", "maintainer_domain", "key_uid_domain", "os_id", "rpm_vendor", "path",
    "hardware_vendor",
)


class KB:
    def __init__(self, vendors=None, lifecycle=None, files=None):
        self.vendors = vendors or {}
        self.lifecycle = lifecycle or {}
        self.files = files or []

    @classmethod
    def load(cls, extra_dirs=()):
        dirs = [REPO_KB, SITE_KB]
        env = os.environ.get("SECDEPMAP_KB_PATH")
        if env:
            dirs += [d for d in env.split(":") if d]
        dirs += list(extra_dirs or ())
        vendors, lifecycle, files = {}, {}, []
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                if not fn.endswith(".json"):
                    continue
                path = os.path.join(d, fn)
                txt = safe_read(path)
                if txt is None:
                    continue
                try:
                    data = json.loads(txt)
                except ValueError as e:
                    raise SystemExit("secdepmap: invalid KB file %s: %s" % (path, e))
                files.append(path)
                for v in data.get("vendors", []):
                    cur = vendors.setdefault(v["id"], {})
                    _deep_merge(cur, v)
                for prod, cycles in (data.get("lifecycle") or {}).items():
                    lifecycle[prod] = cycles
        return cls(vendors, lifecycle, files)

    # ----------------------------------------------------------------------
    def match(self, kind, value):
        """Return vendor id for an identifier, or None."""
        if not value:
            return None
        for vid, v in self.vendors.items():
            pats = (v.get("match") or {}).get(kind)
            if pats and glob_match(str(value), pats):
                return vid
        return None

    def match_any(self, pairs):
        for kind, value in pairs:
            vid = self.match(kind, value)
            if vid:
                return vid
        return None

    def vendor_for_domain(self, host):
        """Match by url_host first, then by any vendor 'domains' entry."""
        vid = self.match("url_host", host)
        if vid:
            return vid
        rd = reg_domain(host)
        for vid, v in self.vendors.items():
            if rd and rd in [d.lower() for d in v.get("domains", [])]:
                return vid
        return None

    def lifecycle_for(self, product, cycle):
        for c in self.lifecycle.get(product, {}).get("cycles", []):
            if str(c.get("cycle")) == str(cycle):
                return c
        return None


def _deep_merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v


def vendor_node(g, kb, vid=None, fallback_name=None, fallback_domain=None):
    """Create/return the vendor node id for a KB vendor or an unknown one."""
    if vid and vid in kb.vendors:
        v = kb.vendors[vid]
        nid = "vendor:" + vid
        if not g.has(nid):
            g.node(nid, "vendor", v.get("name", vid),
                   kb=True,
                   kind=v.get("kind"),
                   domains=v.get("domains"),
                   links=v.get("links"),
                   contacts=v.get("contacts"),
                   osv_ecosystem=v.get("osv_ecosystem"),
                   support_model=v.get("support_model"),
                   notes=v.get("notes"),
                   links_verified=v.get("links_verified"),
                   cna=v.get("cna"))
        return nid
    key = (fallback_domain or fallback_name or "unknown").lower()
    nid = "vendor:unknown:" + key
    if not g.has(nid):
        g.node(nid, "vendor", (fallback_name or fallback_domain or "Unknown") + " (not in KB)",
               kb=False, domains=[fallback_domain] if fallback_domain else None,
               notes="No curated security information. Add an entry under kb/ or /etc/secdepmap/kb.d/.")
    return nid
