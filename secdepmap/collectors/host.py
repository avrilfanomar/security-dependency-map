"""Host, OS lifecycle, kernel hardening, CPU vulnerabilities, boot chain, accounts."""

from __future__ import annotations

import glob
import os
import platform
import re
import time

from ..kb import vendor_node
from ..util import (debian_version_compare, iso, listdir, parse_date, parse_kv_file, read_first_line,
                    run, safe_read, user_group_names, which)
from . import Status

NAME = "host"
DESCRIPTION = "OS release & support lifecycle, kernel, boot chain, CPU vulnerabilities, sysctl hardening, privileged groups"

TAINT_FLAGS = [
    ("P", "proprietary module loaded"), ("F", "module force-loaded"), ("S", "SMP unsafe"),
    ("R", "module force-unloaded"), ("M", "machine check"), ("B", "bad page"), ("U", "user-requested taint"),
    ("D", "kernel oops/BUG"), ("A", "ACPI table overridden"), ("W", "kernel warning"), ("C", "staging driver"),
    ("I", "firmware bug workaround"), ("O", "out-of-tree module"), ("E", "unsigned module"),
    ("L", "soft lockup"), ("K", "live-patched"), ("X", "auxiliary"), ("T", "struct randomisation"),
    ("N", "test module"),
]

# sysctl -> (secure predicate, severity, why)
SYSCTLS = {
    "kernel/kptr_restrict": (lambda v: v in ("1", "2"), "low", "kernel pointers exposed to unprivileged users"),
    "kernel/dmesg_restrict": (lambda v: v == "1", "low", "unprivileged users can read the kernel log"),
    "kernel/yama/ptrace_scope": (lambda v: v in ("1", "2", "3"), "low", "any process can ptrace other processes of the same user"),
    "kernel/unprivileged_bpf_disabled": (lambda v: v in ("1", "2"), "medium", "unprivileged eBPF enabled (frequent LPE vector)"),
    "kernel/kexec_load_disabled": (lambda v: True, "info", ""),
    "fs/protected_symlinks": (lambda v: v == "1", "medium", "symlink race protection disabled"),
    "fs/protected_hardlinks": (lambda v: v == "1", "medium", "hardlink protection disabled"),
    "fs/suid_dumpable": (lambda v: v in ("0", "2"), "low", "setuid programs may dump core"),
    "kernel/randomize_va_space": (lambda v: v == "2", "medium", "ASLR not fully enabled"),
    "net/ipv4/tcp_syncookies": (lambda v: v == "1", "low", "SYN cookies disabled"),
    "kernel/apparmor_restrict_unprivileged_userns": (lambda v: v == "1", "info", ""),
}
PRIV_GROUPS = {
    "docker": ("medium", "membership is root-equivalent (can mount / into a privileged container)"),
    "lxd": ("medium", "membership is root-equivalent (privileged containers / host mounts)"),
    "incus-admin": ("medium", "membership is root-equivalent"),
    "libvirt": ("low", "can define VMs with host device/disk access"),
    "disk": ("medium", "raw access to block devices (read any file)"),
    "shadow": ("medium", "can read password hashes"),
    "sudo": ("info", "administrator via sudo"),
    "wheel": ("info", "administrator via sudo/su"),
    "adm": ("info", "can read system logs"),
}
OS_PRODUCTS = {"ubuntu": "ubuntu", "debian": "debian", "fedora": "fedora", "rhel": "rhel",
               "rocky": "rocky-linux", "almalinux": "almalinux", "linuxmint": "linuxmint",
               "alpine": "alpine-linux", "opensuse-leap": "opensuse", "centos": "centos"}


def applicable(ctx):
    return True, ""


def collect(ctx, g):
    s = Status()
    kb = ctx.kb
    hid = ctx.host_id
    dmi = {k: read_first_line("/sys/class/dmi/id/" + k) for k in
           ("sys_vendor", "product_name", "product_version", "board_vendor", "bios_vendor", "bios_version", "bios_date")}
    boot_mode = "uefi" if os.path.isdir("/sys/firmware/efi") else "bios"
    g.node(hid, "host", ctx.hostname, arch=platform.machine(), dmi={k: v for k, v in dmi.items() if v},
           boot_mode=boot_mode, virtualization=_virt())

    # ---- OS -------------------------------------------------------------------
    osr = parse_kv_file(safe_read("/etc/os-release") or safe_read("/usr/lib/os-release") or "")
    ctx.shared["os_release"] = osr
    os_id = osr.get("ID", "linux")
    vid = kb.match("os_id", os_id) or next((kb.match("os_id", x) for x in osr.get("ID_LIKE", "").split() if kb.match("os_id", x)), None)
    vnode = vendor_node(g, kb, vid, fallback_name=osr.get("NAME") or os_id)
    ctx.shared["os_vendor"] = vnode
    oid = "os:%s:%s" % (os_id, osr.get("VERSION_ID", "rolling"))
    product = OS_PRODUCTS.get(os_id, os_id)
    cycle = osr.get("VERSION_ID", "")
    lc = kb.lifecycle_for(product, cycle) or (kb.lifecycle_for(product, cycle.split(".")[0]) if cycle else None)
    g.node(oid, "os", osr.get("PRETTY_NAME", os_id), os_id=os_id, version=osr.get("VERSION_ID"),
           codename=osr.get("VERSION_CODENAME"), id_like=osr.get("ID_LIKE"), lifecycle=lc,
           lifecycle_product=product)
    g.edge(hid, oid, "runs")
    g.edge(oid, vnode, "supported_by")
    ctx.shared["os_node"] = oid
    if lc:
        lifecycle_findings(g, oid, osr.get("PRETTY_NAME", os_id), lc)
    else:
        s.note("no offline lifecycle data for %s %s (use --online)" % (product, cycle))

    # ---- kernel ---------------------------------------------------------------
    rel = platform.release()
    kid = "kernel:" + rel
    lsm = (read_first_line("/sys/kernel/security/lsm") or "").split(",")
    lockdown = read_first_line("/sys/kernel/security/lockdown")
    lockdown_mode = re.search(r"\[(\w+)\]", lockdown or "")
    taint = int(read_first_line("/proc/sys/kernel/tainted") or 0)
    taints = [desc for i, (_, desc) in enumerate(TAINT_FLAGS) if taint & (1 << i)]
    cmdline = (read_first_line("/proc/cmdline") or "").split()
    cmd_flags = [c for c in cmdline if re.match(r"^(mitigations|nosmt|spectre|nopti|pti|mds|tsx|l1tf|init|selinux|"
                                                 r"apparmor|security|lockdown|module\.sig_enforce|ipv6\.disable|"
                                                 r"intel_iommu|amd_iommu|iommu|slab_nomerge|init_on_alloc|"
                                                 r"init_on_free|randomize_kstack_offset|debugfs)", c)]
    sig_enforce = read_first_line("/sys/module/module/parameters/sig_enforce")
    installed_kernels = sorted({os.path.basename(p)[len("vmlinuz-"):] for p in glob.glob("/boot/vmlinuz-*")})
    newest = None
    for k in installed_kernels:
        if newest is None or debian_version_compare(_kver(k), _kver(newest)) > 0:
            newest = k
    owner = ctx.resolve_owners(["/boot/vmlinuz-" + rel]).get("/boot/vmlinuz-" + rel)
    taint_mods = []
    for mod in listdir("/sys/module"):
        t = read_first_line("/sys/module/%s/taint" % mod)
        if t:
            taint_mods.append({"module": mod, "taint": t})
    g.node(kid, "kernel", "Linux " + rel, release=rel, version=platform.version(), lsm=[x for x in lsm if x],
           lockdown=lockdown_mode.group(1) if lockdown_mode else None, tainted=taint, taint_reasons=taints,
           tainting_modules=taint_mods or None, cmdline_security_flags=cmd_flags or None,
           module_sig_enforce=sig_enforce, installed_kernels=installed_kernels, newest_installed=newest,
           package=owner)
    g.edge(oid, kid, "kernel")
    if owner:
        ctx.shared.setdefault("pending_edges", []).append((kid, "pkg:deb:%s:%s" % (owner, _deb_arch()), "runs"))
    if "mitigations=off" in cmdline:
        g.finding("kernel.mitigations-off", "high", "CPU vulnerability mitigations disabled on the kernel command line",
                  nodes=[kid], evidence={"cmdline": cmd_flags}, category="platform")
    if newest and newest != rel and debian_version_compare(_kver(newest), _kver(rel)) > 0:
        g.finding("kernel.reboot-pending", "medium", "Running kernel %s is older than installed %s" % (rel, newest),
                  "Kernel security fixes are installed but not active until reboot.", nodes=[kid],
                  remediation="Reboot (or use Livepatch for critical fixes).", category="patching")
    if os.path.exists("/var/run/reboot-required") or os.path.exists("/run/reboot-required"):
        pk = (safe_read("/run/reboot-required.pkgs") or "").split()
        g.finding("os.reboot-required", "medium", "System flags that a reboot is required",
                  evidence={"packages": sorted(set(pk))} if pk else None, category="patching")
    if taint & (1 << 12 | 1 << 13 | 1 << 0):
        g.finding("kernel.tainted", "info", "Kernel is tainted: %s" % ", ".join(taints),
                  "Out-of-tree / unsigned / proprietary modules run with full kernel privileges and are patched "
                  "outside the distribution kernel's security process.",
                  nodes=[kid], evidence={"modules": [m["module"] + " (" + m["taint"] + ")" for m in taint_mods]},
                  category="platform")
    if lockdown_mode and lockdown_mode.group(1) == "none" and boot_mode == "uefi":
        g.finding("kernel.lockdown-off", "info", "Kernel lockdown is not enforced", nodes=[kid], category="platform")
    if "apparmor" not in lsm and "selinux" not in lsm:
        g.finding("kernel.no-mac", "medium", "No mandatory access control LSM (AppArmor/SELinux) active",
                  nodes=[kid], evidence={"lsm": lsm}, category="platform")

    # ---- sysctl hardening -------------------------------------------------------
    sysctl = {}
    for key, (good, sev, why) in SYSCTLS.items():
        v = read_first_line("/proc/sys/" + key)
        if v is None:
            continue
        sysctl[key.replace("/", ".")] = v
        if not good(v) and sev != "info":
            g.finding("sysctl." + key.replace("/", "."), sev, "Weak kernel setting %s = %s" % (key.replace("/", "."), v),
                      why, nodes=[kid], category="platform")
    g.nodes[kid]["attrs"]["sysctl"] = sysctl

    # ---- CPU / platform ---------------------------------------------------------
    cpuinfo = safe_read("/proc/cpuinfo", 1 << 20) or ""
    model = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, re.M)
    micro = re.search(r"^microcode\s*:\s*(\S+)$", cpuinfo, re.M)
    vend = re.search(r"^vendor_id\s*:\s*(\S+)$", cpuinfo, re.M)
    vulns = {}
    for p in sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*")):
        vulns[os.path.basename(p)] = read_first_line(p)
    cpu_id = "platform:cpu"
    cpu_vendor = {"GenuineIntel": "intel", "AuthenticAMD": "amd"}.get(vend.group(1) if vend else "", None)
    g.node(cpu_id, "platform", model.group(1).strip() if model else "CPU", kind="cpu",
           microcode=micro.group(1) if micro else None, vulnerabilities=vulns,
           smt=read_first_line("/sys/devices/system/cpu/smt/control"))
    g.edge(hid, cpu_id, "hardware")
    g.edge(cpu_id, vendor_node(g, kb, cpu_vendor if cpu_vendor in kb.vendors else None,
                               fallback_name=vend.group(1) if vend else "CPU vendor"), "made_by")
    for name, state in vulns.items():
        if state and state.startswith("Vulnerable"):
            g.finding("cpu.vuln." + name, "high", "CPU vulnerable to %s" % name.replace("_", " "),
                      "Kernel reports: %s. Usually fixed by a newer CPU microcode (vendor/BIOS update or the "
                      "distribution's intel-microcode/amd64-microcode package) plus a current kernel." % state,
                      nodes=[cpu_id], evidence={"state": state, "microcode": micro.group(1) if micro else None},
                      refs=["https://docs.kernel.org/admin-guide/hw-vuln/index.html"], category="platform")
        elif state and "SMT vulnerable" in state:
            g.finding("cpu.smt." + name, "low", "%s mitigated but SMT (hyper-threading) remains exposed" % name,
                      state, nodes=[cpu_id], category="platform")

    # ---- boot chain ---------------------------------------------------------------
    sb = None
    for p in glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"):
        raw = safe_read(p, 64, binary=True)
        if raw and len(raw) >= 5:
            sb = raw[4] == 1
    g.nodes[hid]["attrs"]["secure_boot"] = sb
    if boot_mode == "bios":
        g.finding("boot.legacy-bios", "medium", "Legacy BIOS boot: no Secure Boot chain of trust",
                  "Bootloader and kernel integrity are not verified by firmware, so a bootkit or tampered initramfs "
                  "would not be detected at boot.", nodes=[hid],
                  remediation="Convert to UEFI boot with Secure Boot if the hardware supports it.", category="platform")
    elif sb is False:
        g.finding("boot.secure-boot-off", "medium", "UEFI Secure Boot is disabled", nodes=[hid], category="platform")
    bios_date = dmi.get("bios_date")
    if bios_date:
        m = re.match(r"(\d\d)/(\d\d)/(\d{4})", bios_date)
        if m:
            ts = parse_date("%s-%s-%s" % (m.group(3), m.group(1), m.group(2)))
            if ts and time.time() - ts > 4 * 365 * 86400:
                g.finding("firmware.bios-old", "low", "System firmware (BIOS) dated %s" % bios_date,
                          "Firmware older than ~4 years usually lacks microcode and platform fixes (e.g. for "
                          "transient-execution and Intel ME/AMD PSP issues).", nodes=[hid],
                          evidence={"bios_vendor": dmi.get("bios_vendor"), "bios_version": dmi.get("bios_version")},
                          category="platform")

    # ---- accounts -------------------------------------------------------------------
    for u in ctx.users_to_scan():
        groups = user_group_names(u["name"])
        aid = "account:" + u["name"]
        g.node(aid, "account", u["name"], uid=u["uid"], groups=groups)
        g.edge(hid, aid, "account")
        for grp in groups:
            if grp in PRIV_GROUPS and PRIV_GROUPS[grp][0] != "info":
                sev, why = PRIV_GROUPS[grp]
                g.finding("account.group.%s:%s" % (grp, u["name"]), sev,
                          "User %s is in group '%s'" % (u["name"], grp), why.capitalize() + ".",
                          nodes=[aid], remediation="Remove the membership if not needed (gpasswd -d %s %s)." % (u["name"], grp),
                          category="access")
    s.stats.update(os=osr.get("PRETTY_NAME"), kernel=rel, boot=boot_mode, secure_boot=sb)
    return s


def lifecycle_findings(g, oid, name, lc):
    now = time.time()
    eol = parse_date(lc.get("eol")) if isinstance(lc.get("eol"), str) else None
    ext = parse_date(lc.get("extendedSupport")) if isinstance(lc.get("extendedSupport"), str) else None
    if lc.get("eol") is True or (eol and eol < now):
        if ext and ext > now:
            g.finding("os.lifecycle.standard-ended", "high",
                      "%s is past standard security support (ended %s)" % (name, lc.get("eol")),
                      "Only paid/extended support (until %s) delivers fixes now." % lc.get("extendedSupport"),
                      nodes=[oid], category="vendor-coverage")
        else:
            g.finding("os.lifecycle.eol", "critical", "%s is end-of-life (%s)" % (name, lc.get("eol")),
                      "No vendor security updates are produced for this release.", nodes=[oid],
                      remediation="Upgrade to a supported release.", category="vendor-coverage")
    elif eol and eol - now < 180 * 86400:
        g.finding("os.lifecycle.eol-soon", "medium", "%s reaches end of standard support on %s" % (name, lc.get("eol")),
                  nodes=[oid], category="vendor-coverage")


def _kver(k):
    m = re.match(r"^(\d+(?:\.\d+)*)(?:-(\d+))?", k)
    return "%s-%s" % (m.group(1), m.group(2) or "0") if m else k


def _deb_arch():
    r = run(["dpkg", "--print-architecture"], timeout=5)
    return r.out.strip() or "amd64"


def _virt():
    if which("systemd-detect-virt"):
        r = run(["systemd-detect-virt"], timeout=5)
        v = r.out.strip()
        return v if v and v != "none" else None
    return None
