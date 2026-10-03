"""Status document for the web UI, built from the shared host summary.

The page never decides what a state is. This module turns each `HostSummary` into plain data:
the numeric status from `status_for` or the summary's overall status, a text label for it, the
reason, and every component with its own state. Hosts are sorted worst first here, so the page
only renders the order it is given. Unknown and not present are shown as such, never as ok.
"""

from __future__ import annotations

from typing import Any

from .summary import Component, HostSummary

REFRESH_S = 15

STATE_TEXT = {"ok": "OK", "warning": "Warning", "critical": "Critical",
              "unknown": "Unknown", "not_present": "Not present"}
STATUS_TEXT = {0: "OK", 1: "Warning", 2: "Critical"}


def _component(c: Component, label: str | None = None) -> dict[str, Any]:
    return {"name": label or c.name, "value": c.value, "unit": c.unit, "state": c.state,
            "state_text": STATE_TEXT.get(c.state, "Unknown"), "reason": c.reason, "labels": c.labels}


def host_document(s: HostSummary) -> dict[str, Any]:
    status = s.overall_status
    pools = Component("pools", None, "", "unknown", "no pool source is collected on this build")
    return {
        "host": s.host,
        "status": status,
        "status_text": STATUS_TEXT[status],
        "reason": s.overall_reason,
        "last_seen": s.last_seen,
        "unmeasured": list(s.unmeasured),
        "not_present": list(s.not_present),
        "disappeared": list(s.disappeared),
        "open_conditions": list(s.open_conditions),
        "cpu": _component(s.cpu, "CPU"),
        "memory": _component(s.memory, "Memory"),
        "power": _component(s.package_power, "Package power"),
        "temperatures": [_component(c) for c in s.temperatures],
        "raid": [_component(c) for c in s.md_arrays],
        "pools": [_component(pools, "Pools")],
        "disks": [_component(c) for c in s.disks],
        "sources": [_component(c, name) for name, c in sorted(s.sources.items())],
    }


def status_document(summaries: list[HostSummary], now: float) -> dict[str, Any]:
    """All hosts, worst overall status first, then by host name, with the banner text."""
    hosts = sorted((host_document(s) for s in summaries), key=lambda h: (-h["status"], h["host"]))
    if not hosts:
        banner = {"status": 1, "status_text": "Warning", "host": None,
                  "text": "No hosts have reported yet."}
    else:
        worst = hosts[0]
        text = f"{worst['host']}: {worst['status_text']}"
        if worst["reason"]:
            text += f". {worst['reason']}"
        elif worst["status"] == 0:
            text = "All hosts OK"
        banner = {"status": worst["status"], "status_text": worst["status_text"],
                  "host": worst["host"], "text": text}
    return {"generated": now, "refresh_s": REFRESH_S, "banner": banner, "hosts": hosts}
