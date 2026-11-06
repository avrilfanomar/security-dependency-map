"""Small, dependency-free helpers shared by collectors.

Security notes
--------------
* Commands are always executed with an argv list (never a shell), a fixed
  PATH and a sanitised environment, so that a hostile ``PATH`` or
  ``LD_PRELOAD`` in the caller's environment cannot redirect them.
* When running as root we refuse to follow symlinks into, or execute
  binaries from, locations owned by unprivileged users (see ``safe_read``).
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import shutil
import stat
import subprocess
import time

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
# Binaries that live in /usr/local are not trusted when we are root.
ROOT_SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def _search_path() -> str:
    # Test hook for simulating hosts without some tools. Deliberately ignored
    # when running as root: an environment-controlled PATH for a root process
    # is exactly the hijack this module exists to prevent.
    if not IS_ROOT and os.environ.get("SECDEPMAP_TEST_PATH"):
        return os.environ["SECDEPMAP_TEST_PATH"]
    return ROOT_SAFE_PATH if IS_ROOT else SAFE_PATH


def _base_env() -> dict:
    env = {
        "PATH": _search_path(),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "COLUMNS": "512",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "SYSTEMD_PAGER": "",
        "SYSTEMD_COLORS": "0",
    }
    # Keep a few variables that tools legitimately need for user sessions.
    for k in ("HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def which(name: str):
    """Resolve *name* on the safe PATH only."""
    return shutil.which(name, path=_base_env()["PATH"])


class CmdResult:
    __slots__ = ("rc", "out", "err", "missing", "timeout")

    def __init__(self, rc=None, out="", err="", missing=False, timeout=False):
        self.rc, self.out, self.err, self.missing, self.timeout = rc, out, err, missing, timeout

    @property
    def ok(self):
        return self.rc == 0

    def __repr__(self):
        return "CmdResult(rc=%r, missing=%r, timeout=%r)" % (self.rc, self.missing, self.timeout)


def run(argv, timeout=30, env_extra=None, input_text=None) -> CmdResult:
    """Run a command safely; never raises for missing tools or timeouts."""
    exe = argv[0] if os.path.isabs(argv[0]) else which(argv[0])
    if not exe:
        return CmdResult(missing=True)
    env = _base_env()
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(
            [exe] + list(argv[1:]),
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
            universal_newlines=True,
            errors="replace",
        )
        return CmdResult(p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return CmdResult(timeout=True)
    except OSError as e:
        return CmdResult(rc=None, err=str(e), missing=True)


def safe_read(path, max_bytes=4 * 1024 * 1024, binary=False):
    """Read a file defensively.

    Returns ``None`` if unreadable. When running as root, files not owned by
    root are opened with O_NOFOLLOW so a user cannot point a symlink at
    /etc/shadow and get its content echoed into a report.
    """
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if IS_ROOT:
            try:
                lst = os.lstat(path)
            except OSError:
                return None
            if stat.S_ISLNK(lst.st_mode):
                tgt = os.stat(path)
                if lst.st_uid != 0 or tgt.st_uid != 0:
                    return None
            elif lst.st_uid != 0:
                flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None
            with os.fdopen(fd, "rb", closefd=False) as fh:
                data = fh.read(max_bytes)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return None
    if binary:
        return data
    return data.decode("utf-8", errors="replace")


def read_first_line(path):
    t = safe_read(path, 65536)
    return t.strip().splitlines()[0].strip() if t and t.strip() else None


def sha256_file(path, max_bytes=None):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            n = 0
            while True:
                b = fh.read(1 << 20)
                if not b:
                    break
                h.update(b)
                n += len(b)
                if max_bytes and n > max_bytes:
                    return None
    except OSError:
        return None
    return h.hexdigest()


def parse_kv_file(text, sep="="):
    """Parse KEY=VALUE files such as /etc/os-release."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or sep not in line:
            continue
        k, v = line.split(sep, 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def parse_deb822(text):
    """Parse RFC822-style stanzas (dpkg status, deb822 sources, Release files)."""
    stanzas, cur, last = [], {}, None
    for raw in (text or "").splitlines():
        if raw.startswith("#"):
            continue
        if not raw.strip():
            if cur:
                stanzas.append(cur)
            cur, last = {}, None
            continue
        if raw[0] in " \t" and last:
            line = raw.strip()
            cur[last] += "\n" + ("" if line == "." else line)
            continue
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        last = k.strip()
        cur[last] = v.strip()
    if cur:
        stanzas.append(cur)
    return stanzas


def glob_match(value, patterns):
    if not value:
        return False
    v = value.lower()
    return any(fnmatch.fnmatchcase(v, p.lower()) for p in patterns or ())


def host_of(uri):
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^@/]*@)?([^/:]+)", uri or "")
    return m.group(1).lower() if m else None


_MULTI_TLDS = {"co.uk", "org.uk", "ac.uk", "com.au", "com.ua", "org.ua", "co.jp", "com.br", "co.in"}


def reg_domain(host):
    """Very small 'registrable domain' approximation (no PSL dependency)."""
    if not host:
        return None
    host = host.lower().strip(".")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def email_domain(s):
    m = re.search(r"<?[^<>\s@]+@([^<>\s@]+)>?", s or "")
    return m.group(1).lower().strip(">") if m else None


def iso(ts):
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def now_iso():
    return iso(time.time())


def days_between(ts_a, ts_b):
    return (ts_b - ts_a) / 86400.0


def parse_date(s):
    """Parse YYYY-MM-DD (or YYYY-MM) to epoch seconds (UTC)."""
    import calendar

    if not s or not isinstance(s, str):
        return None
    for fmt, n in (("%Y-%m-%d", 10), ("%Y-%m", 7)):
        try:
            return calendar.timegm(time.strptime(s[:n], fmt))
        except ValueError:
            continue
    return None


def human_users(min_uid=1000):
    """Interactive accounts (uid >= min_uid with a real shell and home)."""
    users = []
    txt = safe_read("/etc/passwd") or ""
    for line in txt.splitlines():
        p = line.split(":")
        if len(p) < 7:
            continue
        try:
            uid = int(p[2])
        except ValueError:
            continue
        if uid < min_uid or uid >= 60000:
            continue
        if p[6].endswith(("nologin", "false")):
            continue
        if os.path.isdir(p[5]):
            users.append({"name": p[0], "uid": uid, "home": p[5]})
    return users


def current_user_record():
    uid = os.getuid()
    for u in human_users(0):
        if u["uid"] == uid:
            return u
    return {"name": os.environ.get("USER", str(uid)), "uid": uid, "home": os.path.expanduser("~")}


def user_group_names(username):
    groups = []
    txt = safe_read("/etc/group") or ""
    for line in txt.splitlines():
        p = line.split(":")
        if len(p) >= 4 and username in p[3].split(","):
            groups.append(p[0])
    return groups


def listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def mode_issues(path):
    """Return a list of permission weaknesses for a path that may be executed by others."""
    issues = []
    try:
        st = os.lstat(path)
    except OSError:
        return issues
    if st.st_mode & stat.S_IWOTH and not stat.S_ISLNK(st.st_mode):
        issues.append("world-writable")
    if st.st_mode & stat.S_IWGRP and st.st_gid != 0 and not stat.S_ISLNK(st.st_mode):
        issues.append("group-writable (gid %d)" % st.st_gid)
    if st.st_uid != 0:
        issues.append("owned by uid %d" % st.st_uid)
    return issues


def debian_version_compare(a, b):
    """dpkg version comparison (epoch:upstream-revision). Returns -1/0/1."""

    def split(v):
        epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
        if "-" in rest:
            up, _, rev = rest.rpartition("-")
        else:
            up, rev = rest, "0"
        return int(epoch or 0), up, rev

    def order(c):
        if c == "~":
            return -1
        if c.isdigit():
            return 0
        if not c:
            return 0
        if c.isalpha():
            return ord(c)
        return ord(c) + 256

    def cmp_part(x, y):
        i = j = 0
        while i < len(x) or j < len(y):
            first_diff = 0
            while (i < len(x) and not x[i].isdigit()) or (j < len(y) and not y[j].isdigit()):
                ac = order(x[i]) if i < len(x) else 0
                bc = order(y[j]) if j < len(y) else 0
                if ac != bc:
                    return ac - bc
                i += 1
                j += 1
            while i < len(x) and x[i] == "0":
                i += 1
            while j < len(y) and y[j] == "0":
                j += 1
            while i < len(x) and x[i].isdigit() and j < len(y) and y[j].isdigit():
                if not first_diff:
                    first_diff = ord(x[i]) - ord(y[j])
                i += 1
                j += 1
            if i < len(x) and x[i].isdigit():
                return 1
            if j < len(y) and y[j].isdigit():
                return -1
            if first_diff:
                return first_diff
        return 0

    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = cmp_part(ua, ub) or cmp_part(ra, rb)
    return (c > 0) - (c < 0)
