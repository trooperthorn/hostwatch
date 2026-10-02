# TrueNAS-SVR: measured facts

Measured on 2026-10-02 with owner-run, read-only commands. These are the
basis for the TrueNAS collector and deploy files.

- TrueNAS 26.0.0-BETA.3, kernel 6.18.42-production+truenas, x86_64, AMD Ryzen 5 3600. Hostname TrueNAS-SVR, LAN 10.10.11.98. Docker 29.0.4 (needs sudo for the admin user).
- ghcr.io/trooperthorn/hostwatch:edge pulls anonymously (package is public) and collect-once runs read-only, non-root, cap-drop ALL.
  Result: cpu, memory, hwmon available; rapl unavailable (energy_uj root-only, -r--------); mdraid unavailable (no md); scrutiny not configured.
  Host name reported as the container id under --network none: set HOSTWATCH_HOST_NAME or use host networking.
- RAPL: /sys/class/powercap/intel-rapl:0 and :0:0 present on AMD. Needs group grant via a TrueNAS Post Init script (host changes do not survive updates).
- hwmon: nvme, k10temp, 13x drivetemp. No Super I/O, so no voltages or fans.
- Watchdog: SP5100 TCO timer, timeout 60, state inactive, bootstatus 0. systemd RuntimeWatchdogUSec=0 (not armed), RebootWatchdogUSec=10min. Hangs are not auto-reset today.
- pstore mounted, empty, root-only directory.
- Journal: /var/log/journal and /run/log/journal, group systemd-journal gid 102.
- rasdaemon not installed (inactive, no /var/lib/rasdaemon). No ECC (dmidecode: Error Correction Type None), EDAC has no mc entries.
- No /proc/mdstat. ZFS pools Apps, Stash, Vault, boot-pool. /proc/spl/kstat/zfs/<pool>/state readable unprivileged (ONLINE). /dev/zfs is crw-rw-rw-. `zpool events` works. midclt works (TrueNAS API available).
- Apps pool mirror-0 member partuuid 5e882717-6a5c-41d5-a8df-6d9a72e4af51 has CKSUM 1 after a resilver on 2026-09-28.
- Disks are SATA behind a SAS HBA; smartctl -d sat works (sdb WD181KFGX: 0 realloc/pending/CRC, 31351 POH).
- Scrutiny v0.9.5-omnibus runs as app ix-scrutiny on host port 31054 (InfluxDB 31055).
- NUT: upsc present, no UPS service running.

## TrueNAS API (JSON-RPC 2.0 over WebSocket), measured 2026-10-02 via midclt

Docs: https://api.truenas.com/v26.0/jsonrpc.html. 815 methods. Auth method `auth.login_with_api_key`; roles include READONLY_ADMIN (use that for the container key). WebSocket endpoint path and TLS rules for API keys not stated on that page: verify at deploy (expected wss://<host>/api/current).

Read-only methods to use: system.info, system.boot_id, pool.query, disk.query, disk.temperatures, alert.list, pool.scrub.query.

Observed shapes:
- pool.query: list of {id, name, guid, status ("ONLINE"), healthy (bool), warning (bool), status_code ("FAILING_DEV"), status_detail, size, allocated, free, fragmentation (string "11"), scan {function "RESILVER", state "FINISHED", start_time {"$date": ms}, end_time {"$date": ms}, percentage, errors, ...}, topology {data|log|cache|spare|special|dedup: [vdev]}}.
  vdev: {name, guid, type ("MIRROR"|"DISK"), status, path, device ("sdm1"), disk ("sdm"), unavail_disk, stats {timestamp, read_errors, write_errors, checksum_errors, ops[7], bytes[7], size, allocated, fragmentation (int), self_healed (bytes)}, children [vdev]}.
  Note: healthy=true and warning=true at the same time when a device had a corrected checksum error.
- disk.query: {identifier, name, subsystem, serial, lunid, size, model, rotationrate, type ("SSD"|"HDD"), zfs_guid, bus ("ATA"|"UNKNOWN"), devname, pool, ...}. Options {"limit": N} supported.
- disk.temperatures: {"sda": 37.0, ..., "nvme0n1": 34.85} (Celsius floats, keyed by devname).
- alert.list: {id, uuid, source, klass, args{}, node, key (JSON string), datetime {"$date": ms}, last_occurrence {"$date": ms}, dismissed (bool), level ("CRITICAL"...), formatted (text), one_shot}.
- system.info: {version, hostname "TrueNAS-SVR", physmem, model, cores, physical_cores, loadavg[3], uptime_seconds, boottime {"$date": ms}, datetime, timezone "America/Chicago", system_manufacturer, system_product "MS-7C02", ecc_memory false}.
- Dates are {"$date": epoch milliseconds}.

Apps pool checksum error is on sdm (PNY CS900 1TB SSD, serial PNY253825091701039CA), self_healed 4096 bytes; mirror partner sdl (PNY CS900). TrueNAS alert VolumeStatus for Apps is CRITICAL and dismissed.
