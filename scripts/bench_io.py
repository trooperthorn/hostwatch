"""Reproduce the before and after numbers for the read, commit and encoding savings.

Run it from the repository root with the project's interpreter:

    python scripts/bench_io.py

It works in a temporary directory, makes no network calls and touches no real hardware. It reports
three things:

* pstore CPU for twelve reads of eight 256 KiB records, without and with the record cache;
* commits and bytes written to disk for one simulated minute of outbox work (twelve event passes
  that restate one unchanged marker, three tier entries, one delivery pass of five requests), once
  with the Linux marker (the journal cursor) and once with the Windows marker (the event log
  bookmark), in the old style (marker always staged, one commit per acknowledgement) and in the
  new style;
* CPU and size of encoding 120 points as gzip protobuf and gzip JSON.

Commits are counted from the SQLite statement trace. Bytes and write calls come from the operating
system counters of this process (GetProcessIoCounters on Windows, /proc/self/io on Linux), so run
the script on each platform to get that platform's figures. The outbox code is the same on both; the
bytes differ with the file system.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hostwatch import otlp  # noqa: E402
from hostwatch.events.journal import CURSOR_MARKER  # noqa: E402
from hostwatch.events.pstore import read_pstore  # noqa: E402
from hostwatch.events.winevent import BOOKMARK_MARKER  # noqa: E402
from hostwatch.otel_map import GAUGE, Point  # noqa: E402
from hostwatch.outbox import Outbox  # noqa: E402

RES = {"host.name": "bench"}


def io_counters() -> tuple[int, int]:
    """Return (write calls, bytes written) for this process."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        counters = Counters()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters)]
        kernel.GetProcessIoCounters(kernel.GetCurrentProcess(), ctypes.byref(counters))
        return counters.WriteOperationCount, counters.WriteTransferCount
    fields = dict(line.split(": ") for line in Path("/proc/self/io").read_text().splitlines())
    return int(fields["syscw"]), int(fields["wchar"])


def points(n: int) -> list[Point]:
    return [Point("hostwatch.collector.cpu", "hw.cpu.utilization", "1", GAUGE, 0.5, 1700000000.0 + i, {})
            for i in range(n)]


def pstore_cpu(tmp: Path) -> None:
    root = tmp / "pstore"
    root.mkdir()
    for i in range(8):
        (root / f"dmesg-ramoops-{i}").write_bytes(b"line of old console log\n" * 11000)
    for label, cache in (("before (no cache)", None), ("after (cache)", {})):
        start = time.process_time()
        for _ in range(12):
            read_pstore(root, cache)
        print(f"pstore, 12 reads of 8 records, {label}: {(time.process_time() - start) * 1000:.1f} ms CPU")


def outbox_minute(tmp: Path, marker: str, new_style: bool, *,
                  restaged_before: bool) -> tuple[int, int, int]:
    """One minute of outbox work. restaged_before says whether the old code restaged an unchanged
    marker on every pass: true for the Windows event log bookmark, false for the Linux journal
    cursor, which was already staged only when it changed, so on Linux only ack batching differs."""
    box = Outbox(tmp / f"outbox-{marker}-{new_style}.db")
    box.stage(marker, "v0")
    box.enqueue([], "seed")
    statements: list[str] = []
    box._db.set_trace_callback(lambda sql: statements.append(sql.strip().split(None, 1)[0].upper()) if sql.strip() else None)
    calls0, bytes0 = io_counters()
    for i in range(12):
        if new_style or not restaged_before:
            box.stage(marker, "v0")
        else:
            box._staged[marker] = "v0"  # the old behaviour: restaged on every pass
        box.enqueue([], f"marker-{i}")
    for i in range(3):
        box.enqueue(otlp.build_metrics_requests(f"tier-{i}", RES, points(40), fmt="json", compress=True).requests,
                    f"tier-{i}")
    for i in range(5):
        box.enqueue(otlp.build_metrics_requests(f"send-{i}", RES, points(5), fmt="json", compress=True).requests,
                    f"send-{i}")
    while (req := box.peek()) is not None:
        box.ack(req.seq, commit=not new_style)
    box.commit_acks()
    calls1, bytes1 = io_counters()
    commits = statements.count("COMMIT")
    box.close()
    return commits, calls1 - calls0, bytes1 - bytes0


def outbox_numbers(tmp: Path) -> None:
    for platform, marker, restaged in (("Linux marker (journal cursor)", CURSOR_MARKER, False),
                                       ("Windows marker (event log bookmark)", BOOKMARK_MARKER, True)):
        for new_style in (False, True):
            commits, calls, size = outbox_minute(tmp, marker, new_style, restaged_before=restaged)
            print(f"outbox minute, {platform}, {'after' if new_style else 'before'}: "
                  f"{commits} commits, {calls} write calls, {size} bytes written")


def encoding() -> None:
    pts = points(120)
    for fmt in ("protobuf", "json"):
        start = time.process_time()
        for _ in range(200):
            reqs = otlp.build_metrics_requests("e", RES, pts, fmt=fmt, compress=True).requests
        ms = (time.process_time() - start) * 1000 / 200
        size = sum(len(r.body) for r in reqs)
        print(f"encode 120 points, {fmt} + gzip: {ms:.2f} ms CPU, {size} bytes")


def main() -> None:
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        pstore_cpu(tmp)
        outbox_numbers(tmp)
    encoding()


if __name__ == "__main__":
    main()
