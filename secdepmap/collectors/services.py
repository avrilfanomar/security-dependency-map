"""Network exposure: listening sockets -> systemd unit / process -> binary -> package.

Uses ``ss -e`` which reports each socket's cgroup (hence its systemd unit)
even for sockets owned by other users, so attribution works unprivileged.
Also evaluates host firewall state and systemd sandboxing exposure scores.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re

from ..util import read_first_line, run, safe_read, which
from . import Status

NAME = "services"
DESCRIPTION = "Listening sockets, owning services/processes and packages, host firewall state, systemd hardening scores"

BENIGN_UDP = {5353: "mDNS (service discovery)", 68: "DHCP client", 546: "DHCPv6 client", 1900: "SSDP/UPnP discovery"}


def applicable(ctx):
    return (True, "") if which("ss") or os.path.exists("/proc/net/tcp") else (False, "no ss and no /proc/net")


SS_RE = re.compile(r"^(?P<proto>\S+)\s+(?P<state>\S+)\s+\d+\s+\d+\s+(?P<local>\S+)\s+(?P<peer>\S+)\s*(?P<rest>.*)$")


def parse_ss(text):
    out = []
    for line in text.splitlines():
        m = SS_RE.match(line.strip())
        if not m:
            continue
        d = m.groupdict()
        if d["proto"] not in ("tcp", "udp", "sctp"):
            continue
        local = d["local"]
        addr, _, port = local.rpartition(":")
        iface = None
        if "%" in addr:
            addr, iface = addr.split("%", 1)
        addr = addr.strip("[]")
        rest = d["rest"]
        procs = [{"comm": a, "pid": int(b)} for a, b in re.findall(r'\("([^"]+)",pid=(\d+)', rest)]
        uid = re.search(r"\buid:(\d+)", rest)
        cg = re.search(r"\bcgroup:(\S+)", rest)
        try:
            portn = int(port)
        except ValueError:
            continue
        out.append({"proto": d["proto"], "state": d["state"], "addr": addr, "port": portn, "iface": iface,
                    "procs": procs, "uid": int(uid.group(1)) if uid else None,
                    "cgroup": cg.group(1).encode().decode("unicode_escape") if cg else None})
    return out


def scope_of(addr):
    if addr in ("*", "0.0.0.0", "::"):
        return "all-interfaces"
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    return "private" if ip.is_private else "public"


def unit_of(cgroup):
    if not cgroup:
        return None, None
    parts = cgroup.strip("/").split("/")
    if parts and parts[0] == "system.slice":
        for p in reversed(parts):
            if p.endswith((".service", ".socket", ".scope")):
                return p, "system"
    if parts and parts[0] == "user.slice":
        for p in reversed(parts):
            if p.endswith((".service", ".scope")):
                return p, "user"
    return None, None


def systemctl_show(units, props):
    out = {}
    if not units:
        return out
    r = run(["systemctl", "show", "--no-pager", "-p", ",".join(props)] + sorted(units), timeout=60)
    cur = {}
    for line in r.out.splitlines() + [""]:
        if not line.strip():
            if cur.get("Id"):
                out[cur["Id"]] = cur
            cur = {}
            continue
        k, _, v = line.partition("=")
        cur[k] = v
    return out


def firewall_state(ctx):
    st = {"ufw": None, "nftables": None, "firewalld": None, "filtering": "unknown", "evidence": []}
    ufw = safe_read("/etc/ufw/ufw.conf")
    if ufw is not None:
        st["ufw"] = "enabled" if re.search(r"^ENABLED=yes", ufw, re.M) else "disabled"
        st["evidence"].append("ufw.conf ENABLED=%s" % ("yes" if st["ufw"] == "enabled" else "no"))
    for svc in ("nftables", "firewalld"):
        r = run(["systemctl", "is-active", svc + ".service"], timeout=10)
        if r.out.strip():
            st[svc] = r.out.strip()
    if st["firewalld"] == "active":
        st["filtering"] = "yes"
        st["evidence"].append("firewalld active")
    if st["ufw"] == "enabled":
        st["filtering"] = "yes"
    if ctx.is_root and which("nft"):
        r = run(["nft", "-j", "list", "ruleset"], timeout=20)
        try:
            rs = json.loads(r.out).get("nftables", [])
            chains = [x["chain"] for x in rs if "chain" in x and x["chain"].get("hook") == "input"]
            rules = [x["rule"] for x in rs if "rule" in x]
            dropping = any(c.get("policy") == "drop" for c in chains) or any(
                ('"drop"' in json.dumps(ru) or '"reject"' in json.dumps(ru)) and
                any(ru.get("chain") == c.get("name") and ru.get("table") == c.get("table") for c in chains)
                for ru in rules)
            st["nft_input_chains"] = len(chains)
            st["filtering"] = "yes" if dropping else ("no" if st["filtering"] != "yes" else "yes")
            st["evidence"].append("live nft ruleset: %d input chain(s), drop/reject=%s" % (len(chains), dropping))
        except (ValueError, AttributeError):
            pass
    elif st["filtering"] != "yes":
        conf = safe_read("/etc/nftables.conf")
        if st["nftables"] == "active" and conf is not None:
            body = "\n".join(l for l in conf.splitlines() if not l.strip().startswith("#"))
            m = re.search(r"chain\s+input\s*\{(.*?)\n\s*\}", body, re.S)
            inp = m.group(1) if m else ""
            if "policy drop" in inp or re.search(r"\b(drop|reject)\b", inp):
                st["filtering"] = "probably"
                st["evidence"].append("/etc/nftables.conf input chain drops/rejects (live ruleset needs root)")
            else:
                st["filtering"] = "no"
                st["evidence"].append("/etc/nftables.conf input chain accepts everything (static analysis; run as root for live ruleset)")
        elif st["ufw"] == "disabled" and st["nftables"] != "active" and st["firewalld"] != "active":
            st["filtering"] = "no"
            st["evidence"].append("no firewall service active")
    return st


def collect(ctx, g):
    s = Status()
    hid = ctx.host_id

    # ---- running services ---------------------------------------------------
    r = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"], timeout=30)
    running = [ln.split()[0] for ln in r.out.splitlines() if ln.strip()]
    props = ["Id", "MainPID", "ExecStart", "User", "FragmentPath", "Description", "DynamicUser"]
    info = systemctl_show(running, props)

    exposure = {}
    if which("systemd-analyze"):
        er = run(["systemd-analyze", "security", "--no-pager"], timeout=120)
        for line in er.out.splitlines()[1:]:
            p = line.split()
            if len(p) >= 3 and p[0].endswith(".service"):
                try:
                    exposure[p[0]] = (float(p[1]), p[2])
                except ValueError:
                    pass

    # ---- listeners ------------------------------------------------------------
    sr = run(["ss", "-H", "-tulpne"], timeout=30)
    listeners = parse_ss(sr.out) if sr.ok else []
    if not sr.ok:
        s.partial("ss failed; no listener data")
    if listeners and not any(l["cgroup"] for l in listeners):
        s.partial("ss did not report socket cgroups; attribution limited to own processes")

    extra_units = {unit_of(l["cgroup"])[0] for l in listeners if unit_of(l["cgroup"])[1] == "system"} - set(info)
    info.update(systemctl_show(extra_units, props))

    exe_paths = {}
    for u, i in info.items():
        m = re.search(r"path=([^ ;]+)", i.get("ExecStart", ""))
        if m:
            exe_paths[u] = m.group(1)
    proc_exes = {}
    for l in listeners:
        for p in l["procs"]:
            try:
                proc_exes[p["pid"]] = os.readlink("/proc/%d/exe" % p["pid"])
            except OSError:
                pass
    owners = ctx.resolve_owners(sorted(set(exe_paths.values()) | set(proc_exes.values())))

    def pkg_node_for(path):
        own = owners.get(path)
        if not own:
            # unmanaged executable? link to the unmanaged node if that collector saw it
            for cand in ("pkg:unmanaged:" + path,):
                if g.has(cand):
                    return cand
            return None
        for nid in ("pkg:deb:%s:%s" % (own, a) for a in ("amd64", "arm64", "all", "i386", "armhf", "riscv64", "ppc64el", "s390x")):
            if g.has(nid):
                return nid
        rpm = "pkg:rpm:" + own
        return rpm if g.has(rpm) else None

    def service_node(unit):
        sid = "service:" + unit
        if g.has(sid):
            return sid
        i = info.get(unit, {})
        exe = exe_paths.get(unit)
        exp = exposure.get(unit)
        g.node(sid, "service", unit, description=i.get("Description"), exec=exe,
               user=i.get("User") or ("dynamic" if i.get("DynamicUser") == "yes" else "root"),
               main_pid=int(i["MainPID"]) if i.get("MainPID", "0").isdigit() and i.get("MainPID") != "0" else None,
               unit_file=i.get("FragmentPath"), exposure=exp[0] if exp else None, exposure_rating=exp[1] if exp else None,
               package=owners.get(exe) if exe else None)
        g.edge(hid, sid, "runs_service")
        pn = pkg_node_for(exe) if exe else None
        if pn:
            g.edge(sid, pn, "runs")
        return sid

    for u in running:
        service_node(u)

    fw = firewall_state(ctx)
    g.nodes[hid]["attrs"]["firewall"] = fw
    exposed_tcp = []
    user_eph = {}
    for l in listeners:
        scope = scope_of(l["addr"])
        lid = "listener:%s:%s:%d" % (l["proto"], l["addr"] if l["addr"] not in ("*", "0.0.0.0") else "0.0.0.0", l["port"])
        if l["addr"] == "::":
            lid = "listener:%s:[::]:%d" % (l["proto"], l["port"])
        unit, kind = unit_of(l["cgroup"])
        label = "%s %s:%d" % (l["proto"], "*" if scope == "all-interfaces" else l["addr"], l["port"])
        # Ephemeral ports of per-user session processes (browsers, chat apps) change on every run. Key those
        # listeners by process+protocol+scope so snapshots and diffs stay stable instead of flapping.
        ephemeral = kind != "system" and l["port"] >= 32768 and l["procs"] and scope not in ("loopback", "multicast")
        if ephemeral:
            comm = l["procs"][0]["comm"]
            lid = "listener:%s:ephemeral:%s:%s" % (l["proto"], comm, scope)
            label = "%s ephemeral ports (%s, %s)" % (l["proto"], comm, scope)
            prev = g.nodes.get(lid, {}).get("attrs", {}).get("ports", [])
            ports = sorted(set(prev) | {l["port"]})
            g.node(lid, "listener", label, proto=l["proto"], address=l["addr"], port=None, ports=ports, ephemeral=True,
                   scope=scope, uid=l["uid"], unit=unit, processes=[comm])
        else:
            g.node(lid, "listener", label, proto=l["proto"], address=l["addr"], port=l["port"], scope=scope,
                   iface=l["iface"], uid=l["uid"], cgroup=l["cgroup"], unit=unit,
                   processes=[p["comm"] for p in l["procs"]] or None)
        g.edge(hid, lid, "listens")
        target = None
        if unit and kind == "system":
            target = service_node(unit)
        elif l["procs"]:
            p = l["procs"][0]
            pid_n = "process:%s" % p["comm"]
            if unit:
                g.node(pid_n, "service", p["comm"])
            exe = proc_exes.get(p["pid"])
            g.node(pid_n, "service", p["comm"], kind="user-process", exec=exe, unit=unit, package=owners.get(exe) if exe else None)
            pn = pkg_node_for(exe) if exe else None
            if pn:
                g.edge(pid_n, pn, "runs")
            target = pid_n
        if target:
            g.edge(lid, target, "bound_by")
        if scope in ("loopback",):
            continue
        if scope == "multicast" and l["proto"] == "udp":
            continue
        if kind == "user" and l["procs"]:
            svc_name = "%s (user session process)" % l["procs"][0]["comm"]
        else:
            svc_name = unit or (l["procs"][0]["comm"] if l["procs"] else "unknown process")
        if l["proto"] == "udp" and l["port"] in BENIGN_UDP:
            continue
        if ephemeral:
            user_eph.setdefault((l["proto"], svc_name), []).append((l["port"], lid, target))
            continue
        sev = {"no": "high", "unknown": "medium", "probably": "low", "yes": "low"}[fw["filtering"]]
        if l["proto"] == "udp" and sev == "high":
            sev = "medium"
        exp = exposure.get(unit) if unit else None
        g.finding("net.exposed:%s:%d" % (l["proto"], l["port"]), sev,
                  "%s/%d reachable from the network (%s, %s)" % (l["proto"].upper(), l["port"], svc_name, scope),
                  "Bound to %s. Host firewall filtering: %s (%s).%s" % (
                      "all interfaces" if scope == "all-interfaces" else l["addr"], fw["filtering"],
                      "; ".join(fw["evidence"]) or "no evidence",
                      (" systemd sandboxing exposure %.1f (%s)." % exp) if exp else ""),
                  nodes=[lid] + ([target] if target else []),
                  remediation="Bind the service to 127.0.0.1 if remote access is not needed, or restrict with a firewall "
                              "(e.g. 'sudo ufw enable' + explicit allow rules).", category="exposure")
        if l["proto"] == "tcp":
            exposed_tcp.append(l["port"])
    for (proto, name), items in user_eph.items():
        g.finding("net.user-ephemeral:%s:%s" % (proto, name.split()[0]), "low",
                  "%s has %d %s socket(s) on ephemeral ports bound to all interfaces" % (name, len(items), proto.upper()),
                  "Typical for browsers/media apps (WebRTC, cast/mDNS discovery). Reachable from the LAN while no firewall "
                  "filters inbound traffic. Point-in-time: these ports change between runs.",
                  nodes=sorted({x[1] for x in items}) + [x[2] for x in items if x[2]][:1],
                  evidence={"ports": sorted(x[0] for x in items)}, category="exposure")
    if fw["filtering"] == "no" and exposed_tcp:
        g.finding("net.firewall.none", "high", "No host firewall filtering while %d TCP port(s) are exposed" % len(set(exposed_tcp)),
                  "; ".join(fw["evidence"]), nodes=[hid], evidence=fw,
                  remediation="sudo ufw default deny incoming && sudo ufw enable (then allow what you need).",
                  category="exposure")
    for unit, (score, rating) in exposure.items():
        sid = "service:" + unit
        if g.has(sid) and any(e["dst"] == sid and e["rel"] == "bound_by" and
                              g.nodes[e["src"]]["attrs"].get("scope") not in ("loopback", "multicast") for e in g.edges):
            if score >= 9.0:
                g.finding("service.unsandboxed:" + unit, "medium",
                          "Network-facing %s runs with almost no systemd sandboxing (exposure %.1f %s)" % (unit, score, rating),
                          nodes=[sid], remediation="systemctl edit %s  # add ProtectSystem=strict, NoNewPrivileges=yes, ..." % unit,
                          refs=["https://www.freedesktop.org/software/systemd/man/systemd.exec.html"], category="exposure")
    s.stats.update(running_services=len(running), listeners=len(listeners), firewall=fw["filtering"])
    if not ctx.is_root:
        s.note("live firewall ruleset requires root; static config analysed instead")
    return s
