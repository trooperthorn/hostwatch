"""Alerts feed the Alerts and events group and the host status; a partly unmeasured group is not Good."""

from __future__ import annotations

from test_grouped_summary import H, NOW, mediain_rows, row, truenas_rows

from hostwatch.integrations.summary import (build_host_summary, group_documents, grouped_document,
                                            grouped_host_document)


class EventStore:
    """A fake store whose events honour the host, kind, source and since filters."""

    def __init__(self, rows, sources, events=()):
        self._rows, self._sources = rows, sources
        self._events = [dict(e, id=i, host=H, boot_id=None) for i, e in enumerate(events, start=1)]

    def latest(self, host=None):
        return self._rows

    def sources(self):
        return self._sources

    def events(self, host=None, since=None, kind=None, limit=100, source=None, **kw):
        out = [e for e in self._events if (since is None or e["ts"] >= since)
               and (kind is None or e["kind"] == kind) and (source is None or e["source"] == source)]
        return sorted(out, key=lambda e: (e["ts"], e["id"]), reverse=True)[:limit]


def tn_alert(uuid, severity, ts, dismissed=False, text="Pool tank is degraded"):
    return {"ts": ts, "kind": "truenas.alert", "severity": "info" if dismissed else severity, "source": "truenas",
            "title": text, "detail": {"uuid": uuid, "dismissed": dismissed, "formatted": text}}


def host_of(rows, sources, events=(), **opts):
    s = build_host_summary(EventStore(rows, sources, events), H, NOW, **opts)
    return s, {g["id"]: g for g in group_documents(s)}


def test_critical_active_truenas_alert_makes_alerts_and_host_critical_and_not_collapsed():
    rows, sources = truenas_rows()
    base, _ = host_of(rows, sources)
    assert base.overall_status == 1  # the unreadable rapl source, before any alert
    s, groups = host_of(rows, sources, [tn_alert("u1", "critical", NOW - 100)])
    assert groups["alerts"]["status"] == "critical"
    assert "degraded" in groups["alerts"]["summary"]
    doc = grouped_host_document(s)
    assert doc["status_key"] == "critical" and doc["status"] == 2
    # The page opens a host exactly when its status is not good.
    assert doc["status_key"] != "good"
    banner = grouped_document([s], NOW)["banner"]
    assert banner["status_key"] == "critical" and "degraded" in banner["text"]


def test_warning_alert_raises_a_host_whose_other_groups_are_all_good():
    rows, sources = mediain_rows()
    rows = [r for r in rows if not (r["metric"] == "temp" and r["value"] > 100)]
    s, groups = host_of(rows, sources, [tn_alert("u1", "warning", NOW - 10)])
    assert groups["alerts"]["status"] == "warning"
    assert all(g["status"] == "good" for gid, g in groups.items() if gid != "alerts")
    assert s.overall_status == 1
    assert grouped_host_document(s)["status_key"] == "warning"


def test_dismissed_alert_alone_leaves_alerts_good():
    rows, sources = mediain_rows()
    rows = [r for r in rows if not (r["metric"] == "temp" and r["value"] > 100)]
    s, groups = host_of(rows, sources, [tn_alert("u1", "critical", NOW - 100, dismissed=True)])
    alerts = groups["alerts"]
    assert alerts["status"] == "good"
    assert alerts["members"][0]["reason"].startswith("informational: dismissed")
    assert s.overall_status == 0


def test_dismissal_of_the_same_alert_replaces_the_active_one():
    rows, sources = mediain_rows()
    events = [tn_alert("u1", "critical", NOW - 200), tn_alert("u1", "critical", NOW - 100, dismissed=True)]
    _, groups = host_of(rows, sources, events)
    assert len(groups["alerts"]["members"]) == 1 and groups["alerts"]["status"] == "good"


def test_last_boot_classification_is_an_informational_member():
    rows, sources = mediain_rows()
    boot = {"ts": NOW - 500, "kind": "boot.clean_shutdown", "severity": "info", "source": "boot",
            "title": "Previous boot ended", "detail": {}}
    _, groups = host_of(rows, sources, [boot])
    member = groups["alerts"]["members"][0]
    assert member["status"] == "good" and "clean_shutdown" in member["reason"]


def test_recent_warning_events_count_inside_the_window_only():
    rows, sources = mediain_rows()
    event = {"ts": NOW - 3600, "kind": "nut.on_battery", "severity": "warning", "source": "nut",
             "title": "UPS on battery", "detail": {}}
    _, inside = host_of(rows, sources, [event])
    assert inside["alerts"]["status"] == "warning"
    _, outside = host_of(rows, sources, [event], alert_window_s=1800.0)
    assert outside["alerts"]["status"] == "good"
    info = dict(event, severity="info")
    _, quiet = host_of(rows, sources, [info])
    assert quiet["alerts"]["status"] == "good"


def test_group_with_one_good_and_one_unreadable_member_is_unknown_and_names_it():
    rows, sources = mediain_rows()
    rows = [r for r in rows if r["source"] != "mdraid"]
    rows += [row("mdraid", "degraded", 0, array="md0")]
    rows += [row("hwmon", "temp", 40.0, chip="coretemp", sensor="Core 0")]
    rows = [r for r in rows if not (r["metric"] == "temp" and r["value"] > 100)]
    s, groups = host_of(rows, sources)
    assert groups["raid"]["status"] == "good"
    # Make one disk unreadable beside a good one.
    rows += [row("scrutiny", "device_status", 0, wwn="w2", device="sdb", model="m")]
    rows[-1]["ts"] = NOW - 100000  # stale sample: the member cannot be known
    s, groups = host_of(rows, sources)
    disks = groups["disks"]
    assert [m["status"] for m in disks["members"]].count("good") >= 1
    assert disks["status"] == "unknown"
    assert "Not measured" in disks["summary"] and "sdb" in disks["summary"]
    assert s.overall_status >= 1


def test_host_status_equals_worst_group_status_in_every_fixture():
    rank = {"good": 0, "warning": 1, "unknown": 1, "critical": 2}
    cases = []
    for build in (mediain_rows, truenas_rows):
        rows, sources = build()
        cases += [(rows, sources, []),
                  (rows, sources, [tn_alert("u", "critical", NOW - 5)]),
                  (rows, sources, [tn_alert("u", "warning", NOW - 5)]),
                  (rows, sources, [tn_alert("u", "critical", NOW - 5, dismissed=True)])]
    for rows, sources, events in cases:
        s, groups = host_of(rows, sources, events)
        worst = max(rank[g["status"]] for g in groups.values())
        assert s.overall_status == worst, (events, {k: g["status"] for k, g in groups.items()})
        assert grouped_host_document(s)["status"] == worst


def test_hidden_group_cannot_leave_the_host_good():
    # Host status is computed from every group, so a preference that hides the alerts group changes nothing.
    rows, sources = mediain_rows()
    s, _ = host_of(rows, sources, [tn_alert("u1", "critical", NOW - 5)])
    assert s.overall_status == 2
