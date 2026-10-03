#!/usr/bin/env bash
# hostwatch Phase 0: host preparation and verification.
#
# Default mode is read-only: it checks the host and reports PASS, FAIL, WARN,
# SKIP, or MANUAL for each item. Nothing is changed unless --apply is given.
#
# Usage:
#   ./host-prep.sh                 # check only (read-only, safe)
#   ./host-prep.sh --json          # check only, machine-readable output
#   sudo ./host-prep.sh --apply --dry-run   # show what --apply would change
#   sudo ./host-prep.sh --apply    # apply fixes, confirming each one
#   sudo ./host-prep.sh --apply --yes       # apply fixes without prompting
#
# Exit codes: 0 = no FAIL results, 1 = one or more FAIL, 2 = usage error.
#
# Status meanings:
#   PASS    requirement met
#   FAIL    requirement not met and fixable by --apply (or by the operator)
#   WARN    works, but degraded or worth attention
#   SKIP    not applicable on this platform
#   MANUAL  cannot be checked from the OS (for example a BIOS setting)

set -u

MODE="check"
DRY_RUN=0
ASSUME_YES=0
JSON=0

for arg in "$@"; do
  case "$arg" in
    --apply) MODE="apply" ;;
    --dry-run) DRY_RUN=1 ;;
    --yes) ASSUME_YES=1 ;;
    --json) JSON=1 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$MODE" == "apply" && "$DRY_RUN" -eq 0 && "$EUID" -ne 0 ]]; then
  echo "--apply changes system configuration and must run as root (use sudo)." >&2
  exit 2
fi

# ---------------------------------------------------------------- platform
ARCH="$(uname -m)"
PLATFORM="generic"
MODEL=""
if [[ -r /proc/device-tree/model ]]; then
  MODEL="$(tr -d '\0' < /proc/device-tree/model)"
  [[ "$MODEL" == Raspberry\ Pi* ]] && PLATFORM="rpi"
fi
if [[ "$PLATFORM" == "generic" && "$ARCH" == "x86_64" ]]; then
  PLATFORM="x86"
fi
UEFI=0
[[ -d /sys/firmware/efi ]] && UEFI=1

# ---------------------------------------------------------------- results
RESULTS=()     # each entry: id|status|detail|fix
FAIL_COUNT=0

record() {
  local id="$1" status="$2" detail="$3" fix="${4:-}"
  RESULTS+=("$id|$status|$detail|$fix")
  [[ "$status" == "FAIL" ]] && FAIL_COUNT=$((FAIL_COUNT + 1))
}

have() { command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

# ---------------------------------------------------------------- checks
check_journal() {
  local storage
  storage="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null \
    | grep -E '^\s*Storage=' | tail -n1 | cut -d= -f2 | tr -d ' ')"
  if [[ "$storage" == "volatile" || "$storage" == "none" ]]; then
    record journal FAIL "journald Storage=$storage discards logs at reboot" journal
  elif [[ -d /var/log/journal ]]; then
    record journal PASS "persistent journal at /var/log/journal"
  else
    record journal FAIL "no /var/log/journal; logs from a crashed boot are lost" journal
  fi
}

check_watchdog() {
  local dev="" usec
  for d in /dev/watchdog0 /dev/watchdog; do [[ -e "$d" ]] && dev="$d" && break; done
  if [[ -z "$dev" ]]; then
    record watchdog_device FAIL "no watchdog device; on x86 try 'modprobe iTCO_wdt', on Pi enable bcm2835_wdt" ""
  else
    local ident=""
    have wdctl && ident="$(wdctl "$dev" 2>/dev/null | awk -F: '/Identity/{gsub(/^ +/,"",$2);print $2}')"
    record watchdog_device PASS "$dev ${ident:+($ident)}"
  fi
  usec="$(systemctl show -p RuntimeWatchdogUSec --value 2>/dev/null)"
  if [[ -z "$usec" || "$usec" == "0" || "$usec" == "infinity" ]]; then
    record watchdog_systemd FAIL "systemd is not feeding the watchdog; a hard hang will not auto-reboot" watchdog
  else
    record watchdog_systemd PASS "RuntimeWatchdog=$usec"
  fi
}

check_pstore() {
  if ! mountpoint -q /sys/fs/pstore 2>/dev/null; then
    record pstore FAIL "/sys/fs/pstore not mounted" ""
    return
  fi
  local backend=""
  [[ -r /sys/module/pstore/parameters/backend ]] && backend="$(cat /sys/module/pstore/parameters/backend)"
  if [[ -n "$backend" && "$backend" != "(null)" ]]; then
    record pstore PASS "backend=$backend; existing records: $(ls /sys/fs/pstore 2>/dev/null | wc -l)"
  elif [[ "$PLATFORM" == "rpi" ]]; then
    record pstore WARN "no pstore backend; Pi needs ramoops via device tree (Phase 2 relies on boot classifier instead)"
  elif [[ "$UEFI" -eq 1 ]]; then
    record pstore WARN "UEFI system but no pstore backend registered; check 'modprobe efi_pstore'"
  else
    record pstore WARN "legacy BIOS boot; no EFI pstore available"
  fi
}

check_packages() {
  local want=(smartmontools lm-sensors)
  [[ "$PLATFORM" == "x86" ]] && want+=(rasdaemon)
  local missing=()
  for p in "${want[@]}"; do pkg_installed "$p" || missing+=("$p"); done
  if [[ ${#missing[@]} -eq 0 ]]; then
    record packages PASS "${want[*]}"
  else
    record packages FAIL "missing: ${missing[*]}" packages
  fi
  if [[ "$PLATFORM" == "x86" ]]; then
    if systemctl is-active --quiet rasdaemon 2>/dev/null; then
      record rasdaemon PASS "rasdaemon active"
    else
      record rasdaemon FAIL "rasdaemon not running; machine-check events will not be recorded" rasdaemon
    fi
  else
    record rasdaemon SKIP "rasdaemon targets x86 MCE/EDAC; not used on $PLATFORM"
  fi
}

check_sensors() {
  local n
  n="$(ls -d /sys/class/hwmon/hwmon* 2>/dev/null | wc -l)"
  local names
  names="$(cat /sys/class/hwmon/hwmon*/name 2>/dev/null | tr '\n' ' ')"
  if [[ "$n" -eq 0 ]]; then
    record hwmon FAIL "no hwmon devices; run 'sudo sensors-detect' after installing lm-sensors" ""
  elif [[ "$PLATFORM" == "x86" ]] && ! ls /sys/class/hwmon/hwmon*/fan*_input /sys/class/hwmon/hwmon*/in*_input >/dev/null 2>&1; then
    record hwmon WARN "hwmon present ($names) but no fan or voltage inputs; load the Super I/O driver with 'sudo sensors-detect'"
  else
    record hwmon PASS "$n devices: $names"
  fi
}

check_power_source() {
  if [[ "$PLATFORM" == "rpi" ]]; then
    if have vcgencmd; then
      local t
      t="$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)"
      if [[ "$t" == "0x0" ]]; then
        record power_source PASS "vcgencmd get_throttled=0x0 (no undervoltage or throttling since boot)"
      else
        record power_source WARN "vcgencmd get_throttled=$t (non-zero: undervoltage or throttling has occurred)"
      fi
    else
      record power_source FAIL "vcgencmd missing; install libraspberrypi-bin or raspi-utils" ""
    fi
  elif [[ -r /sys/class/powercap/intel-rapl:0/energy_uj ]]; then
    record power_source PASS "RAPL readable: $(cat /sys/class/powercap/intel-rapl:0/name)"
  elif [[ -e /sys/class/powercap/intel-rapl:0/energy_uj ]]; then
    record power_source WARN "RAPL present but root-only; container will need it readable (handled in Phase 1)"
  else
    record power_source WARN "no RAPL; CPU power will be unavailable on this host"
  fi
}

check_cmdline() {
  local cmd
  cmd="$(cat /proc/cmdline)"
  if [[ "$PLATFORM" == "rpi" ]]; then
    record cmdline SKIP "Pi uses /boot/firmware/cmdline.txt; not modified by this script"
    return
  fi
  local missing=()
  [[ "$PLATFORM" == "x86" ]] && ! grep -qw 'pcie_aspm=off' <<<"$cmd" && missing+=(pcie_aspm=off)
  grep -qw 'consoleblank=0' <<<"$cmd" || missing+=(consoleblank=0)
  if [[ ${#missing[@]} -eq 0 ]]; then
    record cmdline PASS "running kernel has required parameters"
  elif [[ -f /etc/default/grub.d/hostwatch.cfg ]]; then
    record cmdline WARN "configured in grub.d but not active yet; reboot required"
  else
    record cmdline FAIL "running kernel missing: ${missing[*]}" cmdline
  fi
}

check_sysrq() {
  local v
  v="$(cat /proc/sys/kernel/sysrq 2>/dev/null)"
  if [[ "$v" == "1" ]]; then
    record sysrq PASS "magic SysRq fully enabled"
  else
    record sysrq FAIL "kernel.sysrq=$v; keyboard recovery keys limited during a hang" sysrq
  fi
}

check_raid() {
  if [[ ! -r /proc/mdstat ]] || ! grep -q '^md' /proc/mdstat; then
    record raid SKIP "no md arrays on this host"
    return
  fi
  if grep -qE '\[[U]*_[U_]*\]' /proc/mdstat; then
    record raid FAIL "an md array is degraded: $(grep -E '^md' /proc/mdstat | tr '\n' ' ')" ""
  else
    record raid PASS "$(grep -cE '^md' /proc/mdstat) array(s), all members up"
  fi
}

check_docker() {
  if have docker && systemctl is-active --quiet docker 2>/dev/null; then
    record docker PASS "$(docker --version 2>/dev/null)"
  else
    record docker FAIL "Docker not installed or not running" ""
  fi
}

check_manual() {
  if [[ "$PLATFORM" == "x86" ]]; then
    record bios_ac_restore MANUAL "BIOS: Advanced > APM > Restore AC Power Loss = Power On (cannot be read from the OS)"
  fi
}

run_checks() {
  RESULTS=(); FAIL_COUNT=0
  check_journal; check_watchdog; check_pstore; check_packages; check_sensors
  check_power_source; check_cmdline; check_sysrq; check_raid; check_docker; check_manual
}

# ---------------------------------------------------------------- fixes
confirm() {
  local prompt="$1"
  [[ "$ASSUME_YES" -eq 1 ]] && return 0
  read -r -p "$prompt [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

do_fix() {
  local fix="$1"
  local desc cmds
  case "$fix" in
    journal)
      desc="Create /var/log/journal so journald keeps logs across reboots (uses disk space, capped by journald defaults)."
      cmds='mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal && systemctl restart systemd-journald' ;;
    watchdog)
      desc="Add /etc/systemd/system.conf.d/hostwatch-watchdog.conf (RuntimeWatchdogSec=30s, RebootWatchdogSec=10min). Consequence: if the kernel stops scheduling systemd for 30s, the hardware resets the machine."
      cmds='mkdir -p /etc/systemd/system.conf.d && printf "[Manager]\nRuntimeWatchdogSec=30s\nRebootWatchdogSec=10min\n" > /etc/systemd/system.conf.d/hostwatch-watchdog.conf && systemctl daemon-reexec' ;;
    packages)
      local pk="smartmontools lm-sensors"
      [[ "$PLATFORM" == "x86" ]] && pk="$pk rasdaemon"
      desc="apt install $pk"
      cmds="apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y $pk" ;;
    rasdaemon)
      desc="Enable and start rasdaemon."
      cmds='systemctl enable --now rasdaemon' ;;
    cmdline)
      desc="Write /etc/default/grub.d/hostwatch.cfg appending pcie_aspm=off consoleblank=0, then update-grub. Takes effect at next reboot. /etc/default/grub itself is not edited."
      cmds='mkdir -p /etc/default/grub.d && printf "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT pcie_aspm=off consoleblank=0\"\n" > /etc/default/grub.d/hostwatch.cfg && update-grub' ;;
    sysrq)
      desc="Write /etc/sysctl.d/99-hostwatch-sysrq.conf (kernel.sysrq=1) and apply it."
      cmds='echo "kernel.sysrq=1" > /etc/sysctl.d/99-hostwatch-sysrq.conf && sysctl --system >/dev/null' ;;
    *) return 0 ;;
  esac
  echo
  echo "FIX [$fix]: $desc"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "  dry-run, would run: $cmds"
    return 0
  fi
  if confirm "  Apply?"; then
    if bash -c "$cmds"; then echo "  applied"; else echo "  FAILED (exit $?)"; fi
  else
    echo "  skipped"
  fi
}

# ---------------------------------------------------------------- output
json_escape() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }

print_results() {
  if [[ "$JSON" -eq 1 ]]; then
    printf '{"host":"%s","platform":"%s","arch":"%s","model":"%s","uefi":%s,"fail_count":%d,"checks":[' \
      "$(hostname)" "$PLATFORM" "$ARCH" "$(json_escape "$MODEL")" "$([[ $UEFI -eq 1 ]] && echo true || echo false)" "$FAIL_COUNT"
    local first=1
    for r in "${RESULTS[@]}"; do
      IFS='|' read -r id st detail fix <<<"$r"
      [[ $first -eq 0 ]] && printf ','
      first=0
      printf '{"id":"%s","status":"%s","detail":"%s","fixable":%s}' \
        "$id" "$st" "$(json_escape "$detail")" "$([[ -n "$fix" ]] && echo true || echo false)"
    done
    printf ']}\n'
    return
  fi
  echo "hostwatch Phase 0 check: $(hostname)  platform=$PLATFORM arch=$ARCH uefi=$UEFI ${MODEL:+model=\"$MODEL\"}"
  echo "------------------------------------------------------------------------"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id st detail fix <<<"$r"
    printf '%-7s %-18s %s%s\n' "$st" "$id" "$detail" "$([[ -n "$fix" && "$st" == FAIL ]] && echo '  [--apply fixes]')"
  done
  echo "------------------------------------------------------------------------"
  echo "FAIL: $FAIL_COUNT"
}

# ---------------------------------------------------------------- main
run_checks

if [[ "$MODE" == "apply" ]]; then
  print_results
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id st detail fix <<<"$r"
    [[ "$st" == "FAIL" && -n "$fix" ]] && do_fix "$fix"
  done
  if [[ "$DRY_RUN" -eq 0 ]]; then
    echo
    echo "Re-checking after changes:"
    run_checks
    print_results
  fi
else
  print_results
fi

[[ "$FAIL_COUNT" -eq 0 ]]
