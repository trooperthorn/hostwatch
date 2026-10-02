"""Flat JSON documents for the SolarWinds Orion API Poller.

Each function turns the shared `HostSummary` into one flat dictionary: stable
snake_case keys, numbers only (no nesting, no booleans), and a numeric status
per field group where 0 is ok, 1 is warning and 2 is critical. This follows the
owner's UniFi API Poller pattern; the assumptions are listed in UNVERIFIED.md.

Unavailable values are never reported as zero. The value key is left out, the
group carries `<group>_available` 0 and a `<group>_reason` text, and the group
status is 1 (warning), the same rule the summary applies to an unavailable
source. A group where some items are known reports the worst known status.
"""

from __future__ import annotations

import re
from typing import Any

from .homeassistant import slug as host_slug
from .homeassistant import slug_hash
from .summary import STATUS_WARNING, Component, HostSummary

GROUPS = ("cpu", "memory", "power", "temperatures", "raid", "pools", "disks", "sources")


def slug(text: str) -> str:
    """Make a stable lowercase key fragment from a label value."""
    out = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return out or "unnamed"


def host_keys(hosts: list[str]) -> dict[str, str]:
    """Map each host name to a stable key fragment, using the same rule as Home Assistant.

    The key is the slug of the host name, so it does not move when another host joins. Hosts whose
    slugs collide (case or punctuation only) each get a hash suffix of the exact name.
    """
    groups: dict[str, list[str]] = {}
    for h in hosts:
        groups.setdefault(host_slug(h), []).append(h)
    keys: dict[str, str] = {}
    for base, members in groups.items():
        for h in members:
            keys[h] = base if len(members) == 1 else f"{base}_{slug_hash(h)}"
    return keys


def _group(doc: dict[str, Any], name: str, comps: list[Component]) -> None:
    """Add `<name>_status`, `<name>_available` and, if nothing is known, `<name>_reason`."""
    known = [c.status for c in comps if c.status is not None]
    doc[f"{name}_available"] = 1 if known else 0
    doc[f"{name}_status"] = max(known) if known else STATUS_WARNING
    if not known:
        reasons = sorted({c.reason for c in comps if c.reason})
        doc[f"{name}_reason"] = "; ".join(reasons) if reasons else "no data reported"


def _item(doc: dict[str, Any], key: str, c: Component, value_key: str) -> None:
    if c.value is not None and c.status is not None:
        doc[value_key] = c.value
        doc[f"{key}_status"] = c.status
    else:
        doc[f"{key}_available"] = 0
        doc[f"{key}_reason"] = c.reason or "unavailable"


def _single(s: HostSummary, name: str, c: Component, value_key: str) -> dict[str, Any]:
    doc: dict[str, Any] = {"host": s.host}
    _group(doc, name, [c])
    if c.value is not None and c.status is not None:
        doc[value_key] = c.value
    return doc


def cpu(s: HostSummary) -> dict[str, Any]:
    return _single(s, "cpu", s.cpu, "cpu_utilization_pct")


def memory(s: HostSummary) -> dict[str, Any]:
    return _single(s, "memory", s.memory, "memory_used_pct")


def power(s: HostSummary) -> dict[str, Any]:
    return _single(s, "power", s.package_power, "package_power_w")


def temperatures(s: HostSummary) -> dict[str, Any]:
    doc: dict[str, Any] = {"host": s.host}
    _group(doc, "temperatures", s.temperatures)
    for c in s.temperatures:
        if not c.labels:
            continue  # the placeholder for "no sensor reported" is covered by the group reason
        parts = [slug(c.labels.get("chip") or c.labels.get("device") or c.labels.get("wwn", "")),
                 slug(c.labels.get("sensor") or c.labels.get("wwn", ""))]
        key = "temp_" + "_".join(p for p in dict.fromkeys(parts))
        _item(doc, key, c, f"{key}_c")
    return doc


def raid(s: HostSummary) -> dict[str, Any]:
    doc: dict[str, Any] = {"host": s.host}
    _group(doc, "raid", s.md_arrays)
    for c in s.md_arrays:
        key = "md_" + slug(c.labels.get("array", ""))
        _item(doc, key, c, f"{key}_degraded_devices")
    return doc


def pools(s: HostSummary) -> dict[str, Any]:
    # No storage pool source exists yet (ZFS collection is not built), so this
    # group is honestly unavailable rather than reporting an empty healthy set.
    doc: dict[str, Any] = {"host": s.host}
    _group(doc, "pools", [Component("pools", None, "", "unknown", "no pool source is collected on this build")])
    return doc


def disks(s: HostSummary) -> dict[str, Any]:
    doc: dict[str, Any] = {"host": s.host}
    _group(doc, "disks", s.disks)
    for c in s.disks:
        key = "disk_" + slug(c.labels.get("wwn") or c.labels.get("device", ""))
        _item(doc, key, c, f"{key}_device_status")
    return doc


def sources(s: HostSummary) -> dict[str, Any]:
    doc: dict[str, Any] = {"host": s.host}
    _group(doc, "sources", list(s.sources.values()))
    for name, c in s.sources.items():
        key = "source_" + slug(name)
        doc[f"{key}_up"] = 1 if c.value is not None else 0
        doc[f"{key}_status"] = c.status if c.status is not None else STATUS_WARNING
        if c.value is None and c.reason:
            doc[f"{key}_reason"] = c.reason
    return doc


_BUILDERS = {"cpu": cpu, "memory": memory, "power": power, "temperatures": temperatures,
             "raid": raid, "pools": pools, "disks": disks, "sources": sources}


def group_document(s: HostSummary, group: str) -> dict[str, Any]:
    return _BUILDERS[group](s)


def summary_document(s: HostSummary) -> dict[str, Any]:
    """One flat document: the host, the overall status and every group merged."""
    doc: dict[str, Any] = {"host": s.host}
    doc["overall_available"] = 0 if s.status is None else 1
    doc["overall_status"] = s.overall_status
    doc["overall_unmeasured"] = len(s.unmeasured)
    if s.overall_reason:
        doc["overall_reason"] = s.overall_reason
    if s.last_seen is not None:
        doc["last_seen"] = s.last_seen
    for flag, value in sorted(s.problems.items()):
        if value is not None:
            doc[f"problem_{flag}"] = 1 if value else 0
    doc["open_conditions"] = len(s.open_conditions)
    for g in GROUPS:
        for k, v in _BUILDERS[g](s).items():
            if k != "host":
                doc[k] = v
    return doc
