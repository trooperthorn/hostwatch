#!/usr/bin/env bash
# Grant read access to the kernel pstore (crash records) to the hostwatch
# container group, so the pstore source works without running as root.
#
# Security trade-off (read before running): /sys/fs/pstore is root-only because
# crash dumps can contain fragments of kernel memory, including data that was in
# use when the machine failed. Members of the group can read those fragments.
# For that reason the grant goes only to the dedicated hostwatch-rapl group,
# which is the group the hostwatch container already holds through group_add
# (HOSTWATCH_RAPL_GID). Do not add interactive user accounts to this group.
# The change is read-only: it never gives write access, so records cannot be
# deleted through the group.
#
# What it changes: the group and mode of /sys/fs/pstore (g+rx) and of the files
# in it (g+r), plus a systemd oneshot unit ordered after sys-fs-pstore.mount so
# the grant is repeated at every boot, because pstore is recreated each boot.
# The unit uses After= and ConditionPathIsDirectory=, not Requires=, so on a host where pstore
# is not a separate mount unit the service is skipped instead of failing.
# It also creates the hostwatch-rapl group if it is missing. Nothing else.
#
# Usage:
#   sudo ./pstore-access.sh            confirm, then install the unit and apply now
#   sudo ./pstore-access.sh --yes      same without the confirmation prompt
#   ./pstore-access.sh --dry-run       show what would change (needs no root)
#   sudo ./pstore-access.sh --remove   undo (pstore returns to root-only at next boot)
#
# Set HOSTWATCH_PSTORE_DIR to act on a different tree (used by the tests).
# After a reboot confirm with: ls -ld /sys/fs/pstore

set -euo pipefail
GROUP=hostwatch-rapl
UNIT=/etc/systemd/system/hostwatch-pstore.service
PSTORE="${HOSTWATCH_PSTORE_DIR:-/sys/fs/pstore}"
DRY=0; REMOVE=0; YES=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;; --remove) REMOVE=1 ;; --yes) YES=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg $a" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 || $DRY -eq 1 ]] || { echo "run as root" >&2; exit 2; }

run() { if [[ $DRY -eq 1 ]]; then echo "would run: $*"; else eval "$@"; fi; }

if [[ $REMOVE -eq 1 ]]; then
  run "systemctl disable --now hostwatch-pstore.service 2>/dev/null || true"
  run "rm -f $UNIT && systemctl daemon-reload"
  echo "Removed. pstore reverts to root-only at next boot. The $GROUP group is kept because the RAPL grant uses it."
  exit 0
fi

if [[ $DRY -eq 0 && $YES -eq 0 ]]; then
  echo "This lets members of group $GROUP read kernel crash records, which can contain"
  echo "fragments of kernel memory. Only the hostwatch container should hold this group."
  read -r -p "Continue? [y/N] " ans
  [[ "$ans" == y || "$ans" == Y ]] || { echo "Cancelled, nothing changed."; exit 1; }
fi

run "getent group $GROUP >/dev/null || groupadd --system $GROUP"

# Idempotent: a path that already has the group and the needed group bits is reported ok.
grant() {
  local path="$1" perm="$2" cur bits want=r
  cur="$(stat -c '%G %A' "$path" 2>/dev/null || true)"
  bits="${cur#* }"
  [[ "$perm" == g+rx ]] && want=rx
  if [[ "${cur%% *}" == "$GROUP" && "${bits:4:1}" == r && ( "$want" == r || "${bits:5:1}" == x ) ]]; then
    echo "ok: $path"
    return 0
  fi
  run "chgrp $GROUP '$path'"
  run "chmod $perm '$path'"
}

# Applied now, for the current boot.
if [[ -d "$PSTORE" ]]; then
  grant "$PSTORE" g+rx
  for f in "$PSTORE"/*; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    grant "$f" g+r
  done
else
  echo "no pstore directory at $PSTORE (nothing to grant now; the unit still installs)"
fi

# A oneshot service rather than a udev rule: pstore is a pseudo filesystem mounted
# at boot, so the unit orders itself after its mount.
UNIT_BODY="[Unit]
Description=Allow group $GROUP to read pstore crash records (hostwatch)
After=sys-fs-pstore.mount
ConditionPathIsDirectory=/sys/fs/pstore

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'chgrp $GROUP /sys/fs/pstore && chmod g+rx /sys/fs/pstore; for f in /sys/fs/pstore/*; do [ -f \"\$f\" ] && [ ! -L \"\$f\" ] && chgrp $GROUP \"\$f\" && chmod g+r \"\$f\"; done; true'

[Install]
WantedBy=multi-user.target"

if [[ $DRY -eq 1 ]]; then
  echo "would write $UNIT:"; echo "$UNIT_BODY"
else
  printf '%s\n' "$UNIT_BODY" > "$UNIT"
fi
run "systemctl daemon-reload && systemctl enable --now hostwatch-pstore.service"

if [[ $DRY -eq 0 ]]; then
  echo
  ls -ld "$PSTORE"
  echo "Use the same group id as the RAPL grant: HOSTWATCH_RAPL_GID=$(getent group $GROUP | cut -d: -f3)"
fi
