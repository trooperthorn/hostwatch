"""Group summaries, member labels and the banner use plain words, not metric ids."""

from __future__ import annotations

import re

from test_alerts_status import EventStore, host_of, tn_alert
from test_grouped_summary import H, NOW, mediain_rows, row, src, truenas_rows

from hostwatch.integrations.summary import build_host_summary, group_documents, grouped_document

ID_TEXT = re.compile(r"\b(cpu_utilization|memory_used|package_power|pi_throttling|truenas_alert)\b")


def all_text(groups):
    for g in groups.values():
        yield g["summary"]
        for m in g["members"]:
            yield m["label"]
            yield m["text"]


def assert_plain(groups):
    for text in all_text(groups):
        assert not ID_TEXT.search(text) and "source." not in text, text


def mediain(**extra):
    rows, sources = mediain_rows()
    rows = [r for r in rows if not (r["metric"] == "temp" and r["value"] > 100)]
    rows = [r for r in rows if r["source"] != "mdraid"]
    rows = [r for r in rows if r["metric"] != "utilization_pct"] + [row("cpu", "utilization_pct", 3.2)]
    rows = [r for r in rows if r["metric"] != "mem_available"] + [row("memory", "mem_available", 4757.6)]
    rows = [r for r in rows if r["metric"] != "watts"] + [row("rapl", "watts", 31.04, zone="r0", domain="package-0")]
    rows += [row("mdraid", "degraded", 0, array="md127", level="raid1"),
             row("mdraid", "array_state", 1, array="md127", state="clean"),
             row("mdraid", "sync_action", 1, array="md127", action="idle")]
    return rows, sources


def test_mediain_members_read_in_plain_words_and_round():
    rows, sources = mediain()
    _, groups = host_of(rows, sources)
    assert groups["cpu"]["members"][0]["text"] == "CPU 3 % used"
    assert groups["memory"]["members"][0]["text"] == "Memory 41 % used"
    assert groups["power"]["members"][0]["text"] == "Package 31 W"
    assert groups["raid"]["members"][0]["text"] == "md127 RAID1 clean, idle"
    assert groups["cpu"]["summary"] == "CPU 3 % used"
    # Machine ids stay available in their own field.
    assert groups["cpu"]["members"][0]["id"] == "cpu_utilization"
    assert groups["raid"]["members"][0]["id"] == "md.md127"
    assert_plain(groups)


def test_degraded_raid_keeps_its_severity_word():
    rows, sources = mediain()
    rows = [r for r in rows if r["metric"] != "degraded"] + [row("mdraid", "degraded", 1, array="md127", level="raid1")]
    _, groups = host_of(rows, sources)
    assert groups["raid"]["status"] == "critical"
    assert "degraded" in groups["raid"]["summary"]


def test_truenas_alert_text_has_no_internal_id():
    rows, sources = truenas_rows()
    s, groups = host_of(rows, sources, [tn_alert("u1", "critical", NOW - 100, text="Pool Apps is degraded")])
    member = next(m for m in groups["alerts"]["members"] if m["id"].startswith("truenas_alert."))
    assert member["text"] == "TrueNAS alert: Pool Apps is degraded"
    assert member["label"] == "TrueNAS alert"
    assert groups["alerts"]["status"] == "critical" and "degraded" in groups["alerts"]["summary"]
    assert_plain(groups)


def test_blocked_source_reads_without_prefix_and_with_short_error():
    rows, sources = truenas_rows()
    sources.append(src("pstore", False, 1, "cannot read /host/pstore: [Errno 13] Permission denied: '/host/pstore'"))
    _, groups = host_of(rows, sources)
    member = next(m for m in groups["sources"]["members"] if m["id"] == "source.pstore")
    assert member["text"] == "pstore: cannot read /host/pstore (permission denied)"
    assert member["label"] == "pstore"
    assert member["reason"].startswith("source pstore unavailable")  # raw reason stays for Expert
    assert_plain(groups)


def pi_rows(flags):
    rows = [row("cpu", "utilization_pct", 10.0)]
    for name in ("under_voltage_now", "freq_capped_now", "throttled_now", "soft_temp_limit_now",
                 "under_voltage_occurred", "freq_capped_occurred", "throttled_occurred",
                 "soft_temp_limit_occurred"):
        rows.append(row("rpi", "throttle_flag", 1 if name in flags else 0, flag=name))
    return rows, [src("cpu"), src("rpi")]


def test_pi_throttling_reads_in_plain_words():
    rows, sources = pi_rows({"under_voltage_occurred"})
    _, groups = host_of(rows, sources)
    pi = groups["pi_power"]
    assert pi["status"] == "warning"
    assert pi["members"][0]["text"] == "Under-voltage has occurred since boot"
    assert pi["members"][0]["id"] == "pi_throttling"
    rows, sources = pi_rows({"under_voltage_now", "under_voltage_occurred"})
    _, groups = host_of(rows, sources)
    assert groups["pi_power"]["status"] == "critical"
    assert groups["pi_power"]["summary"] == "Under-voltage now"
    assert_plain(groups)


def test_banner_is_one_short_sentence_without_group_summaries():
    rows, sources = mediain()
    rows = [r for r in rows if r["metric"] != "degraded"] + [row("mdraid", "degraded", 1, array="md127", level="raid1")]
    s = build_host_summary(EventStore(rows, sources), H, NOW)
    banner = grouped_document([s], NOW)["banner"]
    assert banner["text"] == "%s is critical: md127 RAID1 degraded, idle." % H
    assert banner["text"].count(".") == 1
    for g in group_documents(s):
        assert g["summary"] not in banner["text"] or len(g["members"]) == 1
    assert "Raid" not in banner["text"] and "RAID: " not in banner["text"]
    assert banner["counts"]["hosts"]["critical"] == 1


def test_banner_for_a_warning_host_names_status_and_problem():
    rows, sources = pi_rows({"under_voltage_occurred"})
    s = build_host_summary(EventStore(rows, sources), H, NOW)
    banner = grouped_document([s], NOW)["banner"]
    assert banner["text"] == f"{H} is warning: Under-voltage has occurred since boot."


def test_numbers_are_rounded_in_text():
    rows, sources = mediain()
    rows += [row("hwmon", "temp", 52.3456, chip="coretemp", sensor="Core 0")]
    _, groups = host_of(rows, sources)
    texts = [m["text"] for g in groups.values() for m in g["members"]]
    assert "coretemp Core 0 52.3 C" in texts
    for text in texts:
        assert not re.search(r"\d+\.\d{2,}", text), text
