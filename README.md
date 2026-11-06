# secdepmap — security dependency map for a Linux host

`secdepmap` answers four questions about a machine, from live data, with no dependencies beyond Python 3.8+:

1. **What software is here?** (deb, snap, flatpak, pip/pipx/uv, npm, cargo, Node/Rust runtimes, AppImages, loose binaries in `/opt` and `/usr/local`)
2. **Where did each piece come from, and who vouches for it?** (APT repositories and their signing keys, Snap Store assertions, Flatpak remotes, language registries, vendor installers)
3. **Who is the supplier and how do they ship security fixes?** (vendor knowledge base: advisory feeds, disclosure policy, support lifecycle, OSV ecosystem)
4. **What is exposed, and is it still maintained?** (listening sockets → service → binary → package → source, firewall state, EOL runtimes, packages whose repository was disabled or removed)

It produces a graph (JSON, source of truth), a self-contained HTML report with an interactive dependency map, Markdown, Graphviz DOT and Mermaid, plus a list of **findings** with stable IDs so runs can be **diffed**.

```
vendor ──operated_by──▶ source ◀──from── package ◀──runs── service ◀──bound_by── listener
   ▲                       │
   └──issued_by── trust anchor (signing key / assertion root / Web PKI) ◀──signed_by/trusts──┘
```

## Quick start

```sh
git clone <this repo> && cd secdepmap
./bin/secdepmap collect                # as a normal user: writes to ~/.local/state/secdepmap
xdg-open ~/.local/state/secdepmap/report.html

sudo tools/install.sh --timer          # optional: /opt/secdepmap, daily snapshots as root
sudo secdepmap collect                 # root sees the live firewall ruleset, all users' homes, docker
```

| Command | Purpose |
|---|---|
| `secdepmap collect [--online[=eol,securitytxt,osv]] [--only a,b] [--skip a,b] [--format html,md,dot,mermaid] [--fail-on high]` | Take a snapshot, write reports, diff against the previous snapshot |
| `secdepmap findings [--min-severity medium] [--json]` | List findings of the latest snapshot |
| `secdepmap diff OLD NEW [--json] [--exit-code]` | What changed: packages, sources, keys, listeners, findings |
| `secdepmap report SNAPSHOT -f html\|md\|dot\|mermaid\|json [--diff-from OLD]` | Re-render an old snapshot |
| `secdepmap kb info\|show [vendor]\|verify [--write]` | Inspect the vendor KB; re-check every link |
| `secdepmap collectors` | List collectors |

Exit codes: `0` ok, `2` a finding at/above `--fail-on` exists (for CI / cron alerting).

## "Dynamic"

* Every run **re-collects live state**; nothing is cached except opt-in online lookups (24 h).
* Snapshots are timestamped, gzip’d JSON (`snapshots/<host>-<time>.json.gz`, 30 kept by default) and each run diffs against the previous one: new/removed sources, signing keys, listeners, packages, provenance changes, new/resolved findings.
* The vendor KB is data (`kb/*.json`), extended per site in `/etc/secdepmap/kb.d/*.json` or via `$SECDEPMAP_KB_PATH`, without touching code.
* Listeners and processes are **point-in-time**: a socket that is open for 30 s (e.g. a browser’s WebRTC port) may not appear in every run. Use the timer plus `diff` to spot recurring exposure.

## What is collected

| Collector | Sources of truth | Needs root for |
|---|---|---|
| `host` | `/etc/os-release`, `/sys/devices/system/cpu/vulnerabilities`, `/proc`, EFI vars, DMI, `/etc/passwd`+`group` | – |
| `apt` | `/etc/apt/sources.list*` (one-line **and** deb822, disabled/ignored files), keyrings (parsed in pure Python, cross-checked against `gpg`), `InRelease` signers, `dpkg`, `python3-apt` cache, `apt-get -s`, `apt-config`, `pro security-status` | – |
| `snap` | snapd REST API over its unix socket (publisher validation, confinement, interface connections, holds) | – |
| `flatpak` | `flatpak` CLI, remote `gpg-verify`, static sandbox permissions, runtime end-of-life | – |
| `lang` | dist-info / package.json / `.crates2.json` files (never executes pip/npm/cargo), nvm Node versions, pip/npm config | other users’ homes |
| `unmanaged` | `/opt`, `/usr/local`, `~/.local/bin`, AppImages; checks root’s PATH dirs for non-root write access | other users’ homes |
| `services` | `ss -e` (socket → cgroup → systemd unit), `systemctl`, `systemd-analyze security`, firewall config | live nftables ruleset, other users’ process names |
| `firmware` | `fwupdmgr` devices and Host Security ID attributes | – |
| `containers` | docker/podman images and published ports | docker socket access |
| `rpm` | *(experimental)* rpm database, dnf repo files | – |

Each collector reports `ok`, `partial` (e.g. “needs root”), `skipped` (tool absent) or `error`; **a missing tool never aborts a run**, and coverage is shown at the top of every report so a green report can’t hide a blind spot.

### Findings

Severity is about *supply-chain and maintenance posture*, not exploitability of a specific CVE.

| Category | Examples |
|---|---|
| `patching` | packages whose repo is **disabled or removed** (no updates), packages from local `.deb`s, held packages, security fixes only available through Ubuntu Pro/ESM, stale metadata, reboot pending |
| `supply-chain` | `trusted=yes`, non-distro keys trusted **globally**, expired/weak/revoked keys, repositories signed with weak hashes, unverified snap publishers, Flatpak remote without GPG, `extra-index-url` (dependency confusion) |
| `exposure` | listeners on all interfaces with no host firewall, unsandboxed network services, network-facing code from an unmaintained source |
| `vendor-coverage` | EOL OS / runtimes / Flatpak runtimes, vendors with no advisory channel |
| `platform` | CPU vulnerabilities (SMT-aware), legacy BIOS / Secure Boot off, old BIOS, kernel taint, no LSM, weak sysctls, HSI checks |
| `sandbox` | classic/devmode snaps, manually widened snap interfaces, risky Flatpak permissions |
| `access` | `docker`/`lxd` group (root-equivalent), user-writable directories on root’s PATH |
| `vulnerability` | *(only with `--online=osv`)* OSV.dev matches |

Heuristics, not verdicts: provenance of a package that is in no repository is *inferred* from maintainer/homepage domains (edges are marked “likely”). Distribution advisories for universe packages can include CVEs the vendor rates negligible. Read the evidence before acting.

## Security & privacy model

* **Offline by default.** Nothing leaves the machine unless you pass `--online`. Modes: `eol` (endoflife.date), `securitytxt` (RFC 9116 files of vendor domains), `osv` (**sends package names and versions to api.osv.dev**). Each is separate.
* **Reports are sensitive** (software inventory, open ports, key fingerprints, usernames, paths). Files are written `0600`, directories `0700`, `output/`/snapshots are git-ignored, and the HTML report carries a notice. Treat them like a network scan.
* **Safe to run as root.** Commands run via argv (no shell) with a fixed `PATH` and scrubbed environment; the launcher uses `python3 -I`; `/usr/local` is not on root’s command search path; files owned by other users are read with `O_NOFOLLOW`; user-owned code (pip/npm/cargo/nvm) is only *read*, never executed. `tools/install.sh` installs `root:root`, tests the **installed copy**, and never makes the tree writable by users — anything root runs must not be user-editable.
* **Untrusted strings.** Package names, maintainers and descriptions are attacker-influenced. The HTML report embeds data as JSON with `< > &` escaped, parses it with `JSON.parse`, builds the DOM with `textContent` only, only renders `http(s)` links, and has a restrictive CSP (no network, no external assets). Markdown output is escaped. This is covered by tests.
* **No credentials are read.** `.npmrc`/`pip.conf` are inspected for *key names* and risky settings; values are never stored.

## Vendor knowledge base

`kb/vendors.json` maps what hosts actually show (APT `Origin`, URL host, snap publisher, Flatpak remote/app ID, maintainer e-mail domain, key UID domain, `/opt` path, OS ID, hardware vendor) to a vendor and where it publishes security information.

```json
{ "id": "example", "name": "Example Corp", "kind": "software-vendor",
  "domains": ["example.com"],
  "match": { "apt_origin": ["Example"], "url_host": ["apt.example.com"], "key_uid_domain": ["example.com"] },
  "links": { "advisories": "https://example.com/security/advisories", "disclosure_policy": "https://example.com/security" },
  "support_model": "One sentence an engineer can act on." }
```

* Every link must be `https://` (enforced by tests) and is re-checked by `secdepmap kb verify` — **do not add links from memory**; verify them. `kb verify --write` stamps `links_verified`.
* Vendors seen on a host but absent from the KB appear as *“(not in KB)”* with an info finding — the to-do list for your site file.
* `kb/lifecycle.json` is an offline snapshot of endoflife.date (`tools/update-lifecycle.py` refreshes it; `--online=eol` uses the live API).

## Extending

A collector is one module in `secdepmap/collectors/` with `NAME`, `DESCRIPTION`, `applicable(ctx)` and `collect(ctx, graph)`; register it in `collectors/__init__.py:ORDER`. Add nodes/edges with `graph.node()` / `graph.edge()` and findings with `graph.finding(stable_id, severity, title, ...)` — **IDs must be stable across runs** because `diff` keys on them. Return `Status("partial", notes=[...])` rather than raising when something is unavailable. Port ideas: Homebrew, Nix, Go modules, Maven/Gradle, Windows/macOS equivalents of `host`.

## Known limits

* Debian/Ubuntu is the reference platform; RPM support is experimental and untested in CI.
* Without root: the live firewall ruleset, other users’ homes and docker are not visible (reported as `partial`, with a static fallback for `/etc/nftables.conf`/ufw).
* No CVE database is bundled; `--online=osv` uses OSV.dev, and Ubuntu’s ESM-only fixes are reported via `pro security-status`.
* Kernel module and BIOS/firmware CVE matching is not attempted; the tool reports CPU-vulnerability state as the kernel sees it.

## Layout

```
bin/secdepmap            isolated launcher         kb/            vendor + lifecycle data
secdepmap/collectors/    one module per ecosystem  contrib/       systemd service + timer
secdepmap/{model,analyze,diff,enrich,openpgp,kb}.py   tools/     installer, KB refresh
secdepmap/render/        html/md/dot/mermaid       tests/         python3 -I -B -m unittest discover -s tests
```

License: Apache License 2.0 — see [LICENSE](LICENSE).
