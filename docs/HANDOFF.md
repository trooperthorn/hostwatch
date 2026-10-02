# Handoff: history and decisions to date

This records why the project looks the way it does, so later work does not
undo a decision without knowing its reason.

## Origin

MediaIn-SVR is a low-power Debian server built on an older ASUS Z77 board
(optical disc ripping, Docker, an md RAID1 mirror). While tuning BIOS power
settings for low idle draw, the host suffered a hang: local display and SSH
were lost together, the keyboard still triggered a reboot, and no logs
explained it. A newly added dual-port Intel NIC (e1000e, PCIe slot PCIEX16_2,
x4) also failed to initialize with "Hardware Error". hostwatch exists so the
next event is captured with evidence instead of guessed at.

## Hardware and BIOS findings

- Likely hang cause: deep package C-states combined with PCIe ASPM on Ivy
  Bridge. ASPM is not exposed in this BIOS, so it is disabled with
  `pcie_aspm=off`. CPU power management was set to a stability baseline
  (SpeedStep and deeper C-states disabled) and is to be re-enabled in stages:
  Stage 1 SpeedStep + C1E; Stage 2 C3/C6 report + Package C-state C3. Render
  Standby (iGPU RC6) stays disabled until stable. XMP and ASUS MultiCore
  Enhancement are off. Memory Remap must be Enabled. HPET should be Enabled.
- Restore AC Power Loss is set to Power On, so a power cut produces a boot the
  event engine can classify.
- `acpi_enforce_resources=lax` is on the kernel line, but the logged ACPI
  conflicts are in the PMIO/GPIO ranges used by `i2c_i801`, not the NCT6779D
  at 0x290. It may be unnecessary; tracked in `UNVERIFIED.md`.
- Disk health baseline (2026-10-02): md127 clean `[UU]`. sdc has one historical
  UNC read error at 527 power-on hours, no pending or reallocated sectors since
  (about 4,700 hours now); only a short self-test ever run. sdb (boot SSD) has
  4 ICRC errors at 0 power-on hours and `CRC_Error_Count` 213: a link-level
  history. Any growth in 213 means a cable or port problem. Recommended and not
  yet confirmed done: long SMART tests on sda and sdc, an md `check` scrub, and
  a smartd schedule.

## Design decisions

| Decision | Reason |
|---|---|
| Hub and agent split, one image, role by env var | Same build serves MediaIn-SVR (`all`), remote agents (`agent`), and a future Windows agent pushing the same schema. In `all` mode the agent still posts over loopback HTTP so the schema is always exercised. |
| WSL rejected for Windows; native Windows agent planned (Phase 8) | WSL2 is a VM and cannot see host RAPL, physical disks, Storage Spaces, BSODs, or the Windows Event Log. |
| Read-only `/sys`, no host `/proc`, non-root, read-only rootfs, caps dropped | Least privilege. The container needs to read, never write, host state. |
| RAPL via a dedicated group (`scripts/rapl-access.sh`) | Kernel restricts `energy_uj` to root since 5.10 (PLATYPUS, CVE-2020-8694). A group grant keeps the container non-root; the residual side-channel risk is documented and acceptable on a single-tenant host. |
| systemd oneshot instead of udev for RAPL permissions | `intel_rapl_msr` can load after udev coldplug; the service orders after module loading. Still unverified, see `UNVERIFIED.md`. |
| Hardware watchdog via systemd (30s) | Converts a silent hang into an automatic reboot that the Phase 2 boot classifier can identify. |
| Heartbeat-based boot classifier (Phase 2) | Distinguishes clean shutdown, watchdog-caught hang, kernel panic (pstore), and power loss, without a UPS. A smart plug in Home Assistant acts as power-loss witness until a UPS with NUT is added (Phase 6). |
| Raw hwmon values only; no guessed voltage multipliers | Board divider ratios for +12V/+5V are unknown. Calibrate against the BIOS Monitor tab, then write `/etc/sensors.d/` config. |
| SolarWinds integration via Orion API Poller with flat JSON and 0/1/2 status codes | Matches the owner's existing UniFi API Poller pattern. |
| Login with optional mTLS client certificates (Phase 3) | Allows YubiKey/PIV login, consistent with the owner's PKI practice. |

## Open items carried forward

- Deploy and verify Phase 1 on MediaIn-SVR (README "Deploy" and "Verify").
- Confirm Scrutiny `/api/summary` shape (first item to check).
- `lax` removal test, rail calibration, watchdog soak under heavy I/O.
- Re-enable CPU power-management stages and watch for hangs.
- ai-pi Phase 0, deferred.
