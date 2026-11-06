"""Command line interface."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
import traceback

from . import __version__
from .collectors import ORDER, Status, load
from .kb import KB
from .model import SEV_RANK, SEVERITIES, Context, Graph, run_meta
from .util import IS_ROOT, now_iso


def default_state_dir():
    if IS_ROOT:
        return "/var/lib/secdepmap"
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "secdepmap")


def load_snapshot(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def write_private(path, data, mode="w"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, mode) as fh:
        fh.write(data)


def run_collect(args):
    os.umask(0o077)
    kb = KB.load(args.kb or ())
    online = set()
    if args.online:
        from .enrich import MODES
        online = set(MODES) if args.online == "all" else set(x.strip() for x in args.online.split(",") if x.strip())
        bad = online - set(MODES)
        if bad:
            raise SystemExit("unknown --online mode(s): %s (choose from %s)" % (", ".join(sorted(bad)), ", ".join(MODES)))
    state_dir = args.out or default_state_dir()
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    ctx = Context(kb, {"online": online, "hash": args.hash, "state_dir": state_dir})
    g = Graph()
    g.meta = run_meta(ctx)
    g.meta["kb_files"] = kb.files
    only = set(args.only.split(",")) if args.only else None
    skip = set(args.skip.split(",")) if args.skip else set()
    for name in ORDER:
        if name != "host" and ((only and name not in only) or name in skip):
            g.collectors[name] = {"status": "disabled", "notes": ["excluded by --only/--skip"], "stats": {}}
            continue
        mod = load(name)
        t0 = time.time()
        try:
            ok, why = mod.applicable(ctx)
            if not ok:
                st = Status("skipped", [why])
            else:
                if not args.quiet:
                    print("  collecting %-11s %s" % (name, mod.DESCRIPTION[:60]), file=sys.stderr)
                st = mod.collect(ctx, g)
        except Exception as e:  # never let one collector kill the run
            st = Status("error", ["%s: %s" % (type(e).__name__, e)] +
                        traceback.format_exc().strip().splitlines()[-4:])
        d = st.to_dict()
        d["seconds"] = round(time.time() - t0, 2)
        d["description"] = mod.DESCRIPTION
        g.collectors[name] = d

    from .analyze import analyze

    if online:
        from .enrich import enrich
        est = {"status": "ok", "notes": ["modes: " + ",".join(sorted(online))], "stats": {}}
        try:
            enrich(ctx, g, est)
        except Exception as e:
            est["status"] = "error"
            est["notes"].append("%s: %s" % (type(e).__name__, e))
        g.collectors["online"] = est
    analyze(ctx, g)
    snap = g.to_dict()
    snap["meta"]["finished_at"] = now_iso()

    snapdir = os.path.join(state_dir, "snapshots")
    os.makedirs(snapdir, mode=0o700, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ctx.started))
    path = os.path.join(snapdir, "%s-%s.json.gz" % (ctx.hostname, stamp))
    prev = _latest(snapdir, ctx.hostname, exclude=path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb") as gz:
        gz.write(json.dumps(snap, indent=None, separators=(",", ":"), default=str).encode())
    latest = os.path.join(state_dir, "latest.json.gz")
    try:
        if os.path.lexists(latest):
            os.unlink(latest)
        os.symlink(os.path.relpath(path, state_dir), latest)
    except OSError:
        pass

    from .diff import diff, format_text
    dres = None
    if prev:
        try:
            dres = diff(load_snapshot(prev), snap)
            write_private(os.path.join(state_dir, "latest-diff.txt"), format_text(dres) + "\n")
        except (OSError, ValueError, KeyError):
            dres = None
    _prune(snapdir, ctx.hostname, args.keep)

    outputs = [path]
    if not args.no_report:
        from .render import render
        for fmt in args.format.split(","):
            fmt = fmt.strip()
            ext = {"html": "html", "md": "md", "dot": "dot", "mermaid": "mmd"}[fmt]
            rp = os.path.join(state_dir, "report.%s" % ext)
            write_private(rp, render(fmt, snap, dres))
            outputs.append(rp)

    if not args.quiet:
        _print_summary(snap, dres, outputs)
    else:
        print(_one_line(snap, dres, state_dir))
    return _exit_code(snap, args.fail_on)


def _latest(snapdir, host, exclude=None):
    c = sorted(f for f in os.listdir(snapdir) if f.startswith(host + "-") and f.endswith(".json.gz"))
    c = [os.path.join(snapdir, f) for f in c if os.path.join(snapdir, f) != exclude]
    return c[-1] if c else None


def _prune(snapdir, host, keep):
    if keep <= 0:
        return
    c = sorted(f for f in os.listdir(snapdir) if f.startswith(host + "-") and f.endswith(".json.gz"))
    for f in c[:-keep]:
        try:
            os.unlink(os.path.join(snapdir, f))
        except OSError:
            pass


def _exit_code(snap, fail_on):
    if not fail_on:
        return 0
    lim = SEV_RANK[fail_on]
    return 2 if any(SEV_RANK[f["severity"]] <= lim for f in snap["findings"]) else 0


def _one_line(snap, dres, state_dir):
    """Single line for logs/journal: collector health, severity counts and what changed."""
    sev = snap["summary"]["findings_by_severity"]
    cols = ",".join("%s=%s" % (k, v["status"]) for k, v in snap["collectors"].items())
    chg = "no-previous-snapshot" if dres is None else ("changes=none" if dres["empty"] else
          "new_findings=%d resolved_findings=%d pkgs+%d/-%d/~%d" % (
              len(dres["findings_new"]), len(dres["findings_resolved"]), len(dres["packages_added"]),
              len(dres["packages_removed"]), len(dres["packages_changed"])))
    return "secdepmap %s host=%s as=%s findings[%s] collectors[%s] %s state=%s" % (
        __version__, snap["meta"]["hostname"], snap["meta"]["run_as"],
        " ".join("%s=%d" % (k, sev[k]) for k in SEVERITIES), cols, chg, state_dir)


def _print_summary(snap, dres, outputs):
    s = snap["summary"]
    m = snap["meta"]
    print("\nsecdepmap %s - %s (%s) as %s" % (__version__, m["hostname"], m["collected_at"], m["run_as"]))
    cols = snap["collectors"]
    print("collectors: " + "  ".join("%s=%s" % (k, v["status"]) for k, v in cols.items()))
    print("packages:   " + "  ".join("%s=%d" % kv for kv in sorted(s["packages_by_ecosystem"].items())))
    print("graph:      %d nodes, %d edges" % (sum(s["node_types"].values()), len(snap["edges"])))
    sev = s["findings_by_severity"]
    print("findings:   " + "  ".join("%s=%d" % (k, sev[k]) for k in SEVERITIES))
    for f in snap["findings"]:
        if SEV_RANK[f["severity"]] <= SEV_RANK["medium"]:
            print("  [%-8s] %s" % (f["severity"].upper(), f["title"]))
    if dres is not None:
        print("\nchanges since %s: %s" % (dres["from"], "none" if dres["empty"] else
              "%d new / %d resolved findings, %d pkgs added, %d removed, %d changed" % (
                  len(dres["findings_new"]), len(dres["findings_resolved"]), len(dres["packages_added"]),
                  len(dres["packages_removed"]), len(dres["packages_changed"]))))
    print("\nwritten:")
    for o in outputs:
        print("  " + o)


def cmd_report(args):
    from .render import render
    snap = load_snapshot(args.snapshot)
    dres = None
    if args.diff_from:
        from .diff import diff
        dres = diff(load_snapshot(args.diff_from), snap)
    out = render(args.format, snap, dres)
    if args.output and args.output != "-":
        write_private(args.output, out)
        print(args.output)
    else:
        sys.stdout.write(out)
    return 0


def cmd_diff(args):
    from .diff import diff, format_text
    d = diff(load_snapshot(args.old), load_snapshot(args.new))
    print(json.dumps(d, indent=2) if args.json else format_text(d))
    return 1 if (args.exit_code and not d["empty"]) else 0


def cmd_findings(args):
    snap = load_snapshot(args.snapshot or os.path.join(default_state_dir(), "latest.json.gz"))
    lim = SEV_RANK[args.min_severity]
    fl = [f for f in snap["findings"] if SEV_RANK[f["severity"]] <= lim]
    if args.json:
        print(json.dumps(fl, indent=2))
    else:
        for f in fl:
            print("[%-8s] %-14s %s" % (f["severity"].upper(), f["category"], f["title"]))
    return 0


def cmd_collectors(args):
    for name in ORDER:
        mod = load(name)
        print("%-11s %s" % (name, mod.DESCRIPTION))
    return 0


def cmd_kb(args):
    kb = KB.load(args.kb or ())
    if args.kb_cmd == "verify":
        from .kbverify import verify
        return verify(kb, args)
    if args.kb_cmd == "show":
        sel = {k: v for k, v in kb.vendors.items() if not args.vendor or k == args.vendor}
        print(json.dumps(sel, indent=2))
        return 0
    print("KB files:\n  " + "\n  ".join(kb.files))
    print("%d vendors, lifecycle products: %s" % (len(kb.vendors), ", ".join(sorted(kb.lifecycle))))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="secdepmap", description="Security dependency map for a Linux host.")
    p.add_argument("--version", action="version", version="secdepmap " + __version__)
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("collect", help="collect a snapshot, write reports, diff against the previous run")
    c.add_argument("-o", "--out", help="state/output directory (default: %s)" % default_state_dir())
    c.add_argument("--online", nargs="?", const="all", default=None,
                   help="enable online enrichment: all or comma list of eol,securitytxt,osv "
                        "(osv sends package names+versions to api.osv.dev)")
    c.add_argument("--only", help="comma list of collectors to run (host always runs)")
    c.add_argument("--skip", help="comma list of collectors to skip")
    c.add_argument("--hash", action="store_true", help="sha256 unmanaged binaries")
    c.add_argument("--format", default="html,md", help="report formats: html,md,dot,mermaid (default html,md)")
    c.add_argument("--no-report", action="store_true")
    c.add_argument("--keep", type=int, default=30, help="snapshots to keep per host (default 30, 0=all)")
    c.add_argument("--fail-on", choices=SEVERITIES, help="exit 2 if a finding at/above this severity exists")
    c.add_argument("--kb", action="append", help="extra KB directory (repeatable)")
    c.add_argument("-q", "--quiet", action="store_true")

    r = sub.add_parser("report", help="render a snapshot")
    r.add_argument("snapshot")
    r.add_argument("-f", "--format", default="html", choices=["html", "md", "dot", "mermaid", "json"])
    r.add_argument("-o", "--output")
    r.add_argument("--diff-from", help="older snapshot to include a change summary")

    d = sub.add_parser("diff", help="compare two snapshots")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true")
    d.add_argument("--exit-code", action="store_true", help="exit 1 when there are changes")

    f = sub.add_parser("findings", help="list findings of a snapshot (default: latest)")
    f.add_argument("snapshot", nargs="?")
    f.add_argument("--min-severity", default="low", choices=SEVERITIES)
    f.add_argument("--json", action="store_true")

    sub.add_parser("collectors", help="list collectors")

    k = sub.add_parser("kb", help="inspect / verify the vendor knowledge base")
    k.add_argument("kb_cmd", nargs="?", choices=["info", "show", "verify"], default="info")
    k.add_argument("vendor", nargs="?")
    k.add_argument("--kb", action="append")
    k.add_argument("--timeout", type=float, default=10)
    k.add_argument("--json", action="store_true")
    k.add_argument("--write", action="store_true", help="(verify) stamp results into kb/vendors.json")

    args = p.parse_args(argv)
    if args.cmd is None:
        p.print_help()
        return 0
    return {"collect": run_collect, "report": cmd_report, "diff": cmd_diff, "findings": cmd_findings,
            "collectors": cmd_collectors, "kb": cmd_kb}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
