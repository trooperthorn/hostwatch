"""hostwatch-control: the per-host command daemon described in docs/CONTROL.md of the Observe repo.

This package is separate from the read-only collector. No collector module imports it at
import time (`hostwatch.cli` imports `hostwatch.control.daemon` only inside the function that
runs a `control` command), and the collector image works without the optional `control`
extra. It holds the local allowlist loader, the Ed25519 signature check, the ordered checks
that decide whether a command may run, the Linux and Windows executors, the pull loop with its
durable results outbox (`daemon.py`, `outbox.py`) and the Windows service host (`service.py`).
"""
