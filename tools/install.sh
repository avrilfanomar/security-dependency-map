#!/bin/sh
# Install secdepmap system-wide: /opt/secdepmap (root-owned, not writable by users).
#
#   sudo tools/install.sh [--timer] [--no-link] [--prefix /opt/secdepmap]
#
# Why root:root and no group/other write: this tool is meant to be run as root
# (full firewall / socket / home-directory visibility) and optionally from a
# systemd timer. Anything root executes must not be modifiable by an ordinary
# user, otherwise "edit the report script" becomes "become root".
set -eu

PREFIX=/opt/secdepmap
STATE=${SECDEPMAP_STATE_DIR:-/var/lib/secdepmap}
ETC=${SECDEPMAP_ETC_DIR:-/etc/secdepmap}
LINK=1
TIMER=0

while [ $# -gt 0 ]; do
  case "$1" in
    --timer)   TIMER=1 ;;
    --no-link) LINK=0 ;;
    --prefix)  shift; PREFIX=${1:?--prefix needs a path} ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0 $*" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || { echo "Python >= 3.8 required" >&2; exit 1; }

SRC=$(cd "$(dirname "$0")/.." && pwd -P)
[ -f "$SRC/secdepmap/cli.py" ] || { echo "cannot find source tree at $SRC" >&2; exit 1; }

# Refuse to install a tree an unprivileged user could still be modifying.
# (Copying out of a user-writable checkout is fine - the copy is what root runs -
#  but we verify the files we copy are not symlinks pointing elsewhere.)
if find "$SRC/secdepmap" "$SRC/bin" "$SRC/kb" -type l | grep -q .; then
  echo "refusing: symlinks inside the source tree" >&2; exit 1
fi

echo "==> installing to $PREFIX"
install -d -m 0755 -o root -g root "$PREFIX"
# Replace atomically-ish: sync into place, delete files that no longer exist upstream.
for d in bin secdepmap kb contrib docs tools tests; do
  [ -d "$SRC/$d" ] || continue
  rm -rf "$PREFIX/$d.new"
  cp -R "$SRC/$d" "$PREFIX/$d.new"
  find "$PREFIX/$d.new" -name '__pycache__' -prune -exec rm -rf {} +
  chown -R root:root "$PREFIX/$d.new"
  chmod -R go-w,u+rwX,go+rX "$PREFIX/$d.new"
  rm -rf "$PREFIX/$d.old"
  [ -e "$PREFIX/$d" ] && mv "$PREFIX/$d" "$PREFIX/$d.old"
  mv "$PREFIX/$d.new" "$PREFIX/$d"
  rm -rf "$PREFIX/$d.old"
done
for f in README.md LICENSE .gitignore; do
  [ -f "$SRC/$f" ] && install -m 0644 -o root -g root "$SRC/$f" "$PREFIX/$f"
done
chmod 0755 "$PREFIX/bin/secdepmap"

# Test the *installed, root-owned* copy (never the user-writable checkout: running it as root
# would execute user-controlled code, and the tested tree could differ from the deployed one).
echo "==> self-test of installed copy"
if ! python3 -I -B -m unittest discover -s "$PREFIX/tests" >/dev/null 2>&1; then
  echo "!! self-test FAILED for $PREFIX; not linking or enabling anything." >&2
  echo "   run: python3 -I -B -m unittest discover -s $PREFIX/tests -v" >&2
  exit 1
fi

install -d -m 0700 -o root -g root "$STATE"
install -d -m 0755 -o root -g root "$ETC/kb.d"

if [ "$LINK" -eq 1 ]; then
  # /usr/local/bin is root-owned on a sane system; refuse to link into a directory users can write.
  if [ -w /usr/local/bin ] && [ "$(stat -c %U /usr/local/bin)" != root ]; then
    echo "!! /usr/local/bin is not root-owned; skipping symlink" >&2
  else
    ln -sfn "$PREFIX/bin/secdepmap" /usr/local/bin/secdepmap
    echo "==> linked /usr/local/bin/secdepmap"
  fi
fi

if [ "$TIMER" -eq 1 ]; then
  command -v systemctl >/dev/null || { echo "systemd not found; cannot install timer" >&2; exit 1; }
  sed "s#@PREFIX@#$PREFIX#g" "$PREFIX/contrib/systemd/secdepmap.service" > /etc/systemd/system/secdepmap.service
  install -m 0644 "$PREFIX/contrib/systemd/secdepmap.timer" /etc/systemd/system/secdepmap.timer
  systemctl daemon-reload
  systemctl enable --now secdepmap.timer
  echo "==> timer enabled (systemctl list-timers secdepmap.timer)"
fi

echo
echo "Done. Try:  sudo secdepmap collect      # reports land in $STATE (0700)"
echo "            sudo secdepmap collect --online=eol,securitytxt   # opt-in network lookups"
