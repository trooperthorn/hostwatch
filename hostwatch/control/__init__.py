"""hostwatch-control: the per-host command daemon described in docs/CONTROL.md of the watchpost repo.

This package is separate from the read-only collector. Nothing in `hostwatch.agent`,
`hostwatch.hub` or `hostwatch.cli` imports it, and the collector image works without the
optional `control` extra. This slice holds only the verification half: the local allowlist
loader, the Ed25519 signature check and the ordered checks that decide whether a command
may run. Executing actions and talking to watchpost come in later slices.
"""
