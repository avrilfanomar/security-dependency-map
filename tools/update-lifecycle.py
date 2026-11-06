#!/usr/bin/python3 -I
"""Refresh kb/lifecycle.json (offline lifecycle fallback) from endoflife.date.

Usage: tools/update-lifecycle.py [product ...]
The collector uses this file when run without --online; --online=eol always
queries endoflife.date live instead.
"""
import json
import os
import sys
import time
import urllib.request

PRODUCTS = ["ubuntu", "debian", "fedora", "rhel", "rocky-linux", "almalinux", "linuxmint", "alpine-linux",
            "opensuse", "centos", "nodejs", "python", "go"]
KEEP = ("cycle", "codename", "lts", "releaseDate", "eol", "support", "extendedSupport", "latest")
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "kb", "lifecycle.json")


def main(products):
    data = {"_comment": "Offline lifecycle snapshot from https://endoflife.date (CC BY-SA 4.0). "
                        "Regenerate with tools/update-lifecycle.py.",
            "retrieved": time.strftime("%Y-%m-%d"), "lifecycle": {}}
    for p in products:
        req = urllib.request.Request("https://endoflife.date/api/%s.json" % p, headers={"User-Agent": "secdepmap-kb-update"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                cycles = json.loads(r.read())
        except Exception as e:  # noqa: BLE001 - report and continue
            print("skip %s: %s" % (p, e), file=sys.stderr)
            continue
        data["lifecycle"][p] = {"source": "https://endoflife.date/%s" % p,
                                "cycles": [{k: c[k] for k in KEEP if k in c} for c in cycles]}
        print("%-14s %d cycles" % (p, len(cycles)))
    with open(OUT + ".tmp", "w") as fh:
        json.dump(data, fh, indent=1)
        fh.write("\n")
    os.replace(OUT + ".tmp", OUT)
    print("wrote", OUT)


if __name__ == "__main__":
    main(sys.argv[1:] or PRODUCTS)
