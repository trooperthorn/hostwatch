#!/usr/bin/env bash
# Grant read access to RAPL energy counters to a dedicated group, so the
# hostwatch container can read CPU power without running as root.
#
# Security trade-off (read before running): since kernel 5.10 energy_uj is
# root-only because of PLATYPUS (CVE-2020-8694), a side channel that infers
# data from fine-grained energy readings. Members of the hostwatch-rapl group
# regain that ability. On a single-tenant server with no untrusted local users
# the residual risk is low. Do not add interactive user accounts to this group.
#
# Usage:
#   sudo ./rapl-access.sh            install group + boot-time service, apply now
#   sudo ./rapl-access.sh --dry-run  show what would change
#   sudo ./rapl-access.sh --remove   undo everything (counters return to root-only at next boot)

set -euo pipefail
GROUP=hostwatch-rapl
UNIT=/etc/systemd/system/hostwatch-rapl.service
DRY=0; REMOVE=0
for a in "$@"; do
  case "$a" in --dry-run) DRY=1 ;; --remove) REMOVE=1 ;; *) echo "unknown arg $a" >&2; exit 2 ;; esac
done
[[ $EUID -eq 0 || $DRY -eq 1 ]] || { echo "run as root" >&2; exit 2; }

run() { if [[ $DRY -eq 1 ]]; then echo "would run: $*"; else eval "$@"; fi; }

if [[ $REMOVE -eq 1 ]]; then
  run "systemctl disable --now hostwatch-rapl.service 2>/dev/null || true"
  run "rm -f $UNIT && systemctl daemon-reload"
  run "groupdel $GROUP 2>/dev/null || true"
  echo "Removed. Counters revert to root-only at next boot."
  exit 0
fi

run "getent group $GROUP >/dev/null || groupadd --system $GROUP"

# A oneshot service rather than a udev rule: the intel_rapl_msr driver can load
# after udev coldplug, and the service orders itself after module loading.
UNIT_BODY="[Unit]
Description=Allow group $GROUP to read RAPL energy counters (hostwatch)
After=systemd-modules-load.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for f in /sys/class/powercap/intel-rapl:*/energy_uj /sys/class/powercap/intel-rapl:*:*/energy_uj; do [ -e \"\$f\" ] && chgrp $GROUP \"\$f\" && chmod 0440 \"\$f\"; done; true'

[Install]
WantedBy=multi-user.target"

if [[ $DRY -eq 1 ]]; then
  echo "would write $UNIT:"; echo "$UNIT_BODY"
else
  printf '%s\n' "$UNIT_BODY" > "$UNIT"
fi
run "systemctl daemon-reload && systemctl enable --now hostwatch-rapl.service"

if [[ $DRY -eq 0 ]]; then
  echo
  ls -l /sys/class/powercap/intel-rapl:*/energy_uj
  echo
  echo "Set this in deploy/.env:"
  echo "HOSTWATCH_RAPL_GID=$(getent group $GROUP | cut -d: -f3)"
fi
