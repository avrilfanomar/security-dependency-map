"""Firmware inventory and Host Security ID attributes via fwupd (LVFS)."""

from __future__ import annotations

import json

from ..kb import vendor_node
from ..util import run, which
from . import Status

NAME = "firmware"
DESCRIPTION = "fwupd devices (vendor, version, updatability), LVFS remotes, HSI platform security attributes"

HSI_SEVERITY = {1: "medium", 2: "low", 3: "info", 4: "info", 5: "info"}


def applicable(ctx):
    return (True, "") if which("fwupdmgr") else (False, "fwupd not installed")


def _json(argv, timeout=60):
    r = run(argv, timeout=timeout)
    if r.timeout:
        return None
    try:
        return json.loads(r.out)
    except ValueError:
        return None


def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    hid = ctx.host_id
    dev = _json(["fwupdmgr", "get-devices", "--json"]) or {}
    remotes = _json(["fwupdmgr", "get-remotes", "--json"]) or {}
    sec = _json(["fwupdmgr", "security", "--json"], timeout=90) or {}
    if not dev and not sec:
        return Status("skipped", ["fwupd daemon not reachable"])

    lvfs = None
    for r in remotes.get("Remotes", []):
        if r.get("Id") == "lvfs":
            lvfs = {"enabled": r.get("Enabled"), "age_s": r.get("Age"), "uri": r.get("MetadataUri")}
    src = "source:fwupd:lvfs"
    g.node(src, "source", "LVFS (fwupd.org)", ecosystem="firmware", kind="firmware-store",
           uri="https://fwupd.org", enabled=bool(lvfs and lvfs.get("enabled")), lvfs=lvfs,
           trust_scope="signed metadata (PKCS#7/jcat) + vendor-signed capsules")
    g.edge(src, vendor_node(g, kb, "lvfs" if "lvfs" in kb.vendors else None, fallback_name="LVFS"), "operated_by")
    if lvfs and not lvfs.get("enabled"):
        g.finding("firmware.lvfs-disabled", "low", "LVFS firmware metadata remote is disabled",
                  "Firmware updates published by vendors via LVFS will not be offered.", nodes=[src], category="patching")

    n = 0
    for d in dev.get("Devices", []):
        flags = d.get("Flags", [])
        if "internal" not in flags and "updatable" not in flags and not d.get("Version"):
            continue
        did = "firmware:" + (d.get("DeviceId") or d.get("Name", "?"))
        vendor = d.get("Vendor") or ""
        vid = kb.match("hardware_vendor", vendor)
        g.node(did, "firmware", d.get("Name", "device"), vendor=vendor or None, version=d.get("Version"),
               bootloader_version=d.get("VersionBootloader"), plugin=d.get("Plugin"), flags=flags,
               updatable="updatable" in flags, guid=(d.get("Guid") or [None])[0],
               update_state=d.get("UpdateState"), problems=d.get("Problems") or None)
        g.edge(hid, did, "hardware")
        g.edge(did, vendor_node(g, kb, vid, fallback_name=vendor or "unknown hardware vendor"), "made_by")
        if "updatable" in flags:
            g.edge(did, src, "from")
        n += 1

    attrs = sec.get("SecurityAttributes", [])
    bad = []
    for a in attrs:
        if "success" not in (a.get("Flags") or []):
            bad.append({"id": a.get("AppstreamId"), "result": a.get("HsiResult"), "level": a.get("HsiLevel"),
                        "name": a.get("Name") or a.get("AppstreamId"), "actions": [f for f in (a.get("Flags") or []) if f.startswith("action-")]})
    # HSI level = highest L such that every attribute at levels 1..L succeeds (fwupd semantics, simplified)
    hsi = sec.get("HostSecurityId")
    if hsi is None and attrs:
        hsi = 0
        for lvl in range(1, 6):
            at = [a for a in attrs if a.get("HsiLevel") == lvl]
            if at and all("success" in (a.get("Flags") or []) for a in at):
                hsi = lvl
            else:
                break
        hsi = "HSI:%d (computed)" % hsi
    g.nodes[hid]["attrs"]["hsi"] = hsi
    g.nodes[hid]["attrs"]["hsi_failures"] = bad or None
    for b in bad:
        lvl = b["level"]
        aid = (b["id"] or "").replace("org.fwupd.hsi.", "")
        # Several HSI checks duplicate host collector findings (Secure Boot, taint, lockdown) - keep them info.
        dup = aid in ("Uefi.SecureBoot", "Kernel.Tainted", "Kernel.Lockdown")
        if dup or b["result"] == "not-supported":
            sev = "info"
        else:
            sev = HSI_SEVERITY.get(lvl, "info") if lvl else "low"
        hint = {"action-contact-oem": "needs a firmware/BIOS update from the device maker",
                "action-config-fw": "change a firmware (BIOS/UEFI) setting",
                "action-config-os": "change an OS setting"}
        g.finding("hsi." + aid, sev, "Platform security check failed: %s (%s)" % (b["name"], b["result"]),
                  "fwupd Host Security ID attribute at HSI level %s. Remedy: %s." % (
                      lvl or "runtime", "; ".join(hint.get(x, x) for x in b["actions"]) or "see fwupd docs"), nodes=[hid],
                  refs=["https://fwupd.github.io/libfwupdplugin/hsi.html"], category="platform")
    s.stats.update(devices=n, hsi=hsi, hsi_failures=len(bad))
    return s
