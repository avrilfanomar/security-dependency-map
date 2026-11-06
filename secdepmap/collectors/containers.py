"""Container engines: images (registry provenance) and published ports."""

from __future__ import annotations

import json
import os

from ..kb import vendor_node
from ..util import run, which
from . import Status

NAME = "containers"
DESCRIPTION = "Docker/Podman images (registry, age) and containers with published ports"


def applicable(ctx):
    if which("docker") or which("podman"):
        return True, ""
    return False, "no container engine CLI"


def _registry_of(repo):
    first = repo.split("/")[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "docker.io"


def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    engines = 0
    for eng in ("docker", "podman"):
        if not which(eng):
            continue
        if eng == "docker":
            if not os.path.exists("/var/run/docker.sock"):
                s.note("docker daemon not running (no /var/run/docker.sock)")
                continue
            if not ctx.is_root and not os.access("/var/run/docker.sock", os.R_OK | os.W_OK):
                s.partial("docker socket not accessible to this user")
                continue
        info = run([eng, "info", "--format", "{{json .}}"], timeout=20)
        if not info.ok:
            s.note("%s daemon not running / not reachable" % eng)
            continue
        engines += 1
        imgs = run([eng, "images", "--no-trunc", "--format", "{{json .}}"], timeout=60)
        for line in imgs.out.splitlines():
            try:
                im = json.loads(line)
            except ValueError:
                continue
            repo = im.get("Repository") or im.get("repository") or "<none>"
            tag = im.get("Tag") or im.get("tag") or ""
            reg = _registry_of(repo)
            sid = "source:registry:oci:" + reg
            if not g.has(sid):
                g.node(sid, "source", "OCI registry " + reg, ecosystem="oci", kind="container-registry",
                       uri="https://" + reg, enabled=True, trust_scope="TLS + digest pinning (signatures only if enforced)")
                g.edge(sid, vendor_node(g, kb, kb.vendor_for_domain(reg), fallback_domain=reg), "operated_by")
            iid = "image:%s:%s:%s" % (eng, repo, tag)
            g.node(iid, "image", "%s:%s" % (repo, tag), engine=eng, id=im.get("ID"), created=im.get("CreatedAt"),
                   created_since=im.get("CreatedSince"), size=im.get("Size"))
            g.edge(iid, sid, "from")
        ps = run([eng, "ps", "--format", "{{json .}}"], timeout=30)
        for line in ps.out.splitlines():
            try:
                c = json.loads(line)
            except ValueError:
                continue
            ports = c.get("Ports") or ""
            if "0.0.0.0:" in str(ports) or ":::" in str(ports):
                g.finding("container.published:%s" % c.get("Names"), "medium",
                          "Container %s publishes ports on all interfaces (%s)" % (c.get("Names"), ports),
                          "Docker inserts its own iptables rules, so published ports bypass ufw.",
                          category="exposure")
    if not engines and s.status == "ok":
        s.status = "skipped"
    s.stats["engines"] = engines
    return s
