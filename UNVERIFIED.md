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
| Upgrading a real Phase 1 database on MediaIn-SVR leaves samples intact and sets user_version 2 (verified only against a synthetic Phase 1 database in tests) | Copy `/data/hostwatch.db`, run `sqlite3 copy.db "PRAGMA user_version"` (expect 0), start the new hub on the copy, then repeat the pragma (expect 2) and run `SELECT COUNT(*) FROM samples` |
| Hostname inside a `network_mode: host` container matches the host's hostname | `docker exec hostwatch hostname` (set `HOSTWATCH_HOST_NAME` if it differs) |
| An older hub (without the events field) accepts a batch from a newer agent by ignoring the extra field, which is why the wire version was not bumped | Start the Phase 1 hub image, POST a batch containing an `events` list, and expect HTTP 200 (pydantic ignores unknown fields by default; not run against the old image) |
| `/sys/fs/pstore` inside the container (via the read-only `/host/sys` mount) lists the efi_pstore records of the previous boot, and an empty directory means no panic record | After a forced `echo c > /proc/sysrq-trigger` test, `ls -l /sys/fs/pstore` on the host; then `ls /host/sys/fs/pstore` inside the container. Note that systemd-pstore may move records to `/var/lib/systemd/pstore` at boot, which would make the directory empty before the agent looks |
| Boot classifier heuristic: the order is clean flag, then non-empty pstore (kernel_panic), then a watchdog journal hint (watchdog_reset), then an abrupt-journal-end hint (power_loss), else unknown. No age threshold is applied; the heartbeat age is only recorded in the event detail | Run the four exit-test scenarios from PLAN.md Phase 2 on MediaIn-SVR (clean reboot, watchdog hang, panic, power pull) and compare each event's `kind` and `detail` |
| The watchdog_reset and power_loss evidence is not yet wired: the agent passes no journal hints, so today those two kinds never occur and such boots are reported `unknown`. What the journal shows after an iTCO_wdt or systemd runtime-watchdog reset (message text, whether the previous boot's journal is persistent) is unconfirmed | After a deliberate hang (`echo 1 > /proc/sys/kernel/sysrq; echo s > /proc/sysrq-trigger; stop the watchdog feeder`), run `journalctl --list-boots` and `journalctl -b -1 -n 50 --no-pager` and record the final lines and any watchdog message |
| The agent receives SIGTERM before the host powers off in an orderly shutdown, early enough to write the clean flag, and the Docker stop timeout is long enough | `sudo reboot`, then `cat /var/lib/docker/volumes/<data volume>/_data/heartbeat.json` after boot, or check that the next boot's event is `boot.clean_shutdown` |
| `/proc/sys/kernel/random/boot_id` read inside the container equals the host's boot_id, because boot_id is not namespaced | `cat /proc/sys/kernel/random/boot_id` on the host and `docker exec hostwatch cat /proc/sys/kernel/random/boot_id` |
