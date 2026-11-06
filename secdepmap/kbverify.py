"""`secdepmap kb verify` - check that every KB link still resolves.

A security tool must not hand out dead or hijacked advisory links, so links
are re-checked on demand. ``--write`` stamps ``links_verified`` (date) and
``links_failed`` into the repository KB file (maintainers only)."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .enrich import UA
from .kb import REPO_KB


def check(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": UA + " kb-verify", "Accept": "text/html,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(2048)
            return url, r.status, r.geturl()
    except urllib.error.HTTPError as e:
        # 401/403/429 from bot protection still prove the page exists
        return url, e.code, url
    except (urllib.error.URLError, OSError, ValueError) as e:
        return url, None, str(getattr(e, "reason", e))


def verify(kb, args):
    jobs = [(vid, k, u) for vid, v in kb.vendors.items() for k, u in (v.get("links") or {}).items()]
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(lambda j: (j[0], j[1]) + check(j[2], args.timeout), jobs))
    ok_codes = {200, 401, 403, 429}
    bad = [r for r in res if r[3] not in ok_codes]
    if args.json:
        print(json.dumps([{"vendor": r[0], "key": r[1], "url": r[2], "status": r[3], "final": r[4]} for r in res], indent=2))
    else:
        for vid, key, url, code, final in sorted(res):
            flag = "ok " if code in ok_codes else "BAD"
            redirect = "" if final == url or code is None else "  -> " + final
            print("%s %-4s %-14s %-22s %s%s" % (flag, code or "-", vid, key, url, redirect if code else "  (" + final + ")"))
        print("\n%d links, %d failing" % (len(res), len(bad)))
    if getattr(args, "write", False):
        _write(res, ok_codes)
    return 1 if bad else 0


def _write(res, ok_codes):
    path = os.path.join(REPO_KB, "vendors.json")
    with open(path) as fh:
        data = json.load(fh)
    today = time.strftime("%Y-%m-%d")
    by_vendor = {}
    for vid, key, url, code, _ in res:
        by_vendor.setdefault(vid, []).append((key, code in ok_codes))
    for v in data["vendors"]:
        r = by_vendor.get(v["id"])
        if not r:
            continue
        failed = sorted(k for k, ok in r if not ok)
        v["links_verified"] = today
        if failed:
            v["links_failed"] = failed
        else:
            v.pop("links_failed", None)
    with open(path + ".tmp", "w") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(path + ".tmp", path)
    print("updated", path)
