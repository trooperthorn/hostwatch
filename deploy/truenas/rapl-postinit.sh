#!/bin/sh
# Grant the hostwatch-rapl group read access to RAPL energy counters and to the
# pstore crash records after boot.
# Register it in the TrueNAS UI under System > Advanced > Init/Shutdown Scripts
# as a Post Init script, with the --apply argument.
#
# Why it runs every boot: TrueNAS host changes do not survive updates and the
# powercap files are recreated at each boot with root-only permissions.
#
# Consequences, read before using --apply: since kernel 5.10 energy_uj is root-only
# because of the PLATYPUS side channel (CVE-2020-8694). Members of the group regain
# fine-grained energy readings. Only the hostwatch container should hold this gid.
# The script changes the group and mode of energy_uj files under the powercap tree
# and creates the hostwatch-rapl system group if it is missing. Nothing else.
#
# Usage:
#   rapl-postinit.sh             show what would change (default, needs no root)
#   rapl-postinit.sh --dry-run   same as the default
#   rapl-postinit.sh --apply     make the change (must run as root)
#
# pstore: crash dumps in /sys/fs/pstore can contain fragments of kernel memory, so the
# same group, and only that group, gets read and execute on the directory and read on
# its files (chgrp and chmod g+r, never write). Set RAPL_PSTORE_DIR to use another tree.
#
# It is idempotent: a file that already has the group and mode is left alone.
# Set RAPL_POWERCAP_DIR to read a different tree (used by the tests).

set -u
GROUP=hostwatch-rapl
BASE="${RAPL_POWERCAP_DIR:-/sys/class/powercap}"
PSTORE="${RAPL_PSTORE_DIR:-/sys/fs/pstore}"
APPLY=0
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

if [ "$APPLY" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "--apply changes file permissions and must run as root." >&2
  exit 2
fi

if [ "$APPLY" -eq 0 ]; then
  echo "Dry run: nothing will be changed. Use --apply to make the change."
fi

if ! getent group "$GROUP" >/dev/null 2>&1; then
  if [ "$APPLY" -eq 1 ]; then
    groupadd --system "$GROUP" || exit 1
    echo "created group $GROUP"
  else
    echo "would create group $GROUP"
  fi
fi

changed=0
found=0
failed=0
for f in "$BASE"/intel-rapl:*/energy_uj "$BASE"/intel-rapl:*:*/energy_uj; do
  [ -e "$f" ] || continue
  found=1
  current="$(stat -c '%G %a' "$f" 2>/dev/null)"
  if [ "$current" = "$GROUP 440" ]; then
    echo "ok: $f"
    continue
  fi
  changed=$((changed + 1))
  if [ "$APPLY" -eq 1 ]; then
    chgrp "$GROUP" "$f" && chmod 0440 "$f" && echo "granted: $f"
  else
    echo "would grant: $f (now: ${current:-unreadable})"
  fi
done

if [ -d "$PSTORE" ]; then
  for f in "$PSTORE" "$PSTORE"/*; do
    [ -e "$f" ] || continue
    [ -L "$f" ] && continue
    if [ -d "$f" ]; then perm=g+rx; else perm=g+r; fi
    current="$(stat -c '%G %A' "$f" 2>/dev/null)"
    bits="$(stat -c '%A' "$f" 2>/dev/null)"
    have="$(printf '%s' "$bits" | cut -c5)"
    if [ -d "$f" ]; then have="$have$(printf '%s' "$bits" | cut -c6)"; want=rx; else want=r; fi
    if [ "${current%% *}" = "$GROUP" ] && [ "$have" = "$want" ]; then
      echo "ok: $f"
      continue
    fi
    if [ "$APPLY" -eq 1 ]; then
      if chgrp "$GROUP" "$f" && chmod "$perm" "$f"; then
        echo "granted: $f"
      else
        echo "failed to grant: $f" >&2
        failed=1
      fi
    else
      echo "would grant: $f (now: ${current:-unreadable})"
    fi
  done
else
  echo "no pstore directory at $PSTORE"
fi

if [ "$found" -eq 0 ]; then
  echo "no energy_uj files under $BASE (no RAPL zones on this host)"
fi
if getent group "$GROUP" >/dev/null 2>&1; then
  echo "HOSTWATCH group id: $(getent group "$GROUP" | cut -d: -f3)"
fi
[ "$failed" -eq 0 ] || exit 1
exit 0
