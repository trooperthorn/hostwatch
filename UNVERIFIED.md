# Unverified assumptions

Items below are believed correct but have not been confirmed on the target
hosts. Each lists how to verify it. Remove an entry once confirmed.

| Assumption | Verify with |
|---|---|
| ai-pi has `vcgencmd` available | `which vcgencmd` |
| ai-pi exposes `bcm2835_wdt` as `/dev/watchdog0` | `ls /dev/watchdog*; wdctl` |
| `RuntimeWatchdogSec=30s` does not trigger false resets during long optical-drive or md resync I/O | Run a full rip and an md `check` with the watchdog active |
| `acpi_enforce_resources=lax` is required for `nct6775` on MediaIn-SVR (the logged conflicts are in the PMIO/GPIO regions used by `i2c_i801`, not the NCT6779D at 0x290) | Remove `lax` from `/etc/default/grub.d/hostwatch.cfg`, `update-grub`, reboot, then `sudo modprobe nct6775 && sensors` |
| NCT6779D raw inputs `in1`, `in4`, and others map to +12V and +5V through board-specific divider resistors; multipliers unknown | Compare raw `sensors` values against the BIOS Monitor tab readings, then write `/etc/sensors.d/p8z77-v-le-plus.conf` |
| Scrutiny v0.9.5 `GET /api/summary` returns `data.summary.<wwn>.device.{device_name,model_name,serial_number,device_status}` and `.smart.{temp,power_on_hours}` | `curl -s http://127.0.0.1:8081/api/summary \| python3 -m json.tool \| head -40` |
| `hostwatch-rapl.service` runs after `intel_rapl_msr` has created the powercap zones, so permissions are applied at every boot | After a reboot: `ls -l /sys/class/powercap/intel-rapl:0/energy_uj` shows group `hostwatch-rapl` |
| Hostname inside a `network_mode: host` container matches the host's hostname | `docker exec hostwatch hostname` (set `HOSTWATCH_HOST_NAME` if it differs) |
