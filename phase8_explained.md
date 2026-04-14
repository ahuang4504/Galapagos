# Phase 8 Explained — Line by Line

This document walks through every file created or modified in Phase 8 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

Phases 3 through 7 gave the detector heuristics and active verification, but the output path was still fairly ad hoc: alerts were printed directly in `main.py`, and there was no runtime summary showing whether the detector was alive and processing traffic.

Phase 8 adds two things:

1. a dedicated JSON logger for alert and summary output
2. a periodic summary stream with aggregate runtime statistics

```
DNSEvent stream
      │
      ▼
heuristics + verification
      │
      ▼
standardized alert enrichment
      │
      ├── log_alert()   ───► one JSON alert per line
      └── log_summary() ───► one periodic summary JSON object
```

The goal is to make the detector's stdout:

- machine-parseable
- consistent across heuristics
- useful even during quiet periods

That matters because once the detector is running in Docker, you want to be able to do things like:

- `docker compose logs detector`
- pipe output into `jq`
- see periodic proof that the detector is alive even when no alerts fire

---

## Files Added or Modified in Phase 8

Phase 8 touched these files:

- `detector/src/logger.py`
- `detector/src/main.py`
- `tests/test_logger.py`

No new third-party dependencies were added in this phase. The work is entirely about structuring and standardizing existing output.

---

## `detector/src/logger.py`

This file centralizes JSON logging and interval-stat collection.

It contains:

- `log_alert()` for alert JSON output
- `log_summary()` for periodic summary JSON output
- `SummaryStats` for tracking interval counters

---

### Imports

```python
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
```

These imports support three jobs:

- JSON serialization
- interval counting for verification-result statuses
- typed stat storage with a dataclass

`Counter` is used because verification results are categorical values like `MATCH` and `CONFIRMED`, which are naturally counted by label.

---

### Timestamp helper

```python
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
```

This returns a UTC ISO-8601 timestamp string.

It is used for both alerts and summaries so every output object carries the time it was actually logged.

Using one helper keeps the timestamp format consistent.

---

### Alert logger

```python
def log_alert(alert: dict[str, object]) -> None:
    payload = dict(alert)
    payload["logged_at"] = _utc_now_iso()
    print(json.dumps(payload), flush=True)
```

This is the structured alert logger.

Key details:

- `dict(alert)` makes a shallow copy so the caller's alert object is not mutated
- `logged_at` records when the detector emitted the alert
- `json.dumps(...)` ensures one clean JSON object per line
- `flush=True` keeps Docker logs real-time

This replaces direct `print(json.dumps(alert))` calls inside `main.py`.

---

### Summary logger

```python
def log_summary(summary: dict[str, object]) -> None:
    payload = dict(summary)
    payload["logged_at"] = _utc_now_iso()
    print(json.dumps(payload), flush=True)
```

This is almost identical to `log_alert()`, but it is used for periodic runtime summaries.

It keeps the same JSON-lines format as alerts so the entire detector output stream stays consistent.

That means:

- alerts and summaries are both valid standalone JSON objects
- downstream tools can parse the stream line-by-line

---

### Stats dataclass

```python
@dataclass
class SummaryStats:
    interval_events_processed: int = 0
    interval_alerts_fired: int = 0
    interval_verification_results: Counter = field(default_factory=Counter)
```

This class stores interval-local counters between summary emissions.

It tracks:

- how many dnstap events were processed
- how many alerts were emitted
- how many verification results of each status occurred

These are interval counters, not all-time totals. That means every summary describes the most recent reporting window.

---

### Record-event method

```python
def record_event(self) -> None:
    self.interval_events_processed += 1
```

This increments the count every time the detector consumes one `DNSEvent`.

It is called in the main event loop before heuristics run.

---

### Record-alert method

```python
def record_alert(self) -> None:
    self.interval_alerts_fired += 1
```

This increments the interval alert count each time an alert is actually emitted.

This count is based on output alerts, not raw suspicious events before filtering.

---

### Record-verification method

```python
def record_verification(self, status: str) -> None:
    self.interval_verification_results[status] += 1
```

This tracks verification-result statuses like:

- `MATCH`
- `CONFIRMED`
- `VERIFICATION_FAILED`

Using a `Counter` keeps this logic simple and makes the summary output easy to extend if new statuses are added later.

---

### Snapshot-and-reset method

```python
def snapshot(self, interval_seconds: int, queries_tracked: int) -> dict[str, object]:
```

This builds one summary JSON object and then resets the interval counters.

```python
    verification_results = {
        key: self.interval_verification_results.get(key, 0)
        for key in sorted(self.interval_verification_results)
    }
```

This converts the `Counter` into a normal JSON-serializable dictionary and sorts the keys for stable output.

```python
    payload = {
        "type": "summary",
        "interval_seconds": interval_seconds,
        "events_processed": self.interval_events_processed,
        "queries_tracked": queries_tracked,
        "alerts_fired": self.interval_alerts_fired,
        "verification_results": verification_results,
    }
```

This is the summary schema.

Field meanings:

- `type`: identifies this as a summary object rather than an alert
- `interval_seconds`: the reporting interval length
- `events_processed`: events seen during the interval
- `queries_tracked`: current number of pending queries in the Phase 3 matcher
- `alerts_fired`: alerts emitted during the interval
- `verification_results`: counts of verification statuses during the interval

```python
    self.interval_events_processed = 0
    self.interval_alerts_fired = 0
    self.interval_verification_results.clear()
```

After the summary is built, the counters are reset for the next interval.

That makes the summaries reflect recent activity rather than lifetime totals.

---

## `detector/src/main.py`

Phase 8 changes `main.py` from "print alerts directly" to "route alerts and summaries through the logger module".

---

### New imports

```python
from logger import SummaryStats, log_alert, log_summary
```

This brings in both:

- the output functions
- the interval-stat tracker

That separates output concerns from the main detector loop.

---

### Summary interval configuration

```python
SUMMARY_INTERVAL_SECONDS = int(os.getenv("SUMMARY_INTERVAL_SECONDS", "60"))
```

This makes the summary cadence configurable without code changes.

The default is `60` seconds, matching the Phase 8 plan.

That is useful because short intervals are convenient during debugging, while longer intervals are less noisy during longer runs.

---

### Periodic summary coroutine

```python
async def emit_periodic_summaries(
    stats: SummaryStats,
    matcher: QueryResponseMatcher,
) -> None:
```

This coroutine runs in the background while the detector processes dnstap events.

It exists so summaries still appear even if the main event loop is just quietly waiting for traffic.

```python
    while True:
        await asyncio.sleep(SUMMARY_INTERVAL_SECONDS)
```

This makes the coroutine wake up once per configured interval.

```python
        log_summary(
            stats.snapshot(
                interval_seconds=SUMMARY_INTERVAL_SECONDS,
                queries_tracked=len(matcher.pending_queries),
            )
        )
```

This builds and logs one summary object.

The `queries_tracked` field uses the current size of the Phase 3 pending-query store, which is a useful live signal of query-matching state.

---

### Stats object creation

```python
    stats = SummaryStats()
    summary_task = asyncio.create_task(emit_periodic_summaries(stats, matcher))
```

This creates:

- one stats accumulator for the whole run
- one background task that logs interval summaries

The task runs independently of alert processing.

---

### Event counting

```python
            stats.record_event()
```

This increments the processed-event count once per dnstap event before heuristics run.

That means the summary reflects total pipeline load, not just alert activity.

---

### Alert standardization

```python
                domain = extract_alert_domain(alert)
                if domain and "domain" not in alert:
                    alert["domain"] = domain
```

Earlier phases produced slightly different domain field names:

- Phase 3 often used `domain`
- Phase 4 used `target_domain`
- Phase 5 used `query_domain`

Phase 8 standardizes the alert envelope by ensuring every emitted alert has a common `domain` field.

This does not remove the heuristic-specific fields. It just adds a normalized top-level field that downstream tooling can rely on.

That is an important part of the Phase 8 schema cleanup.

---

### Verification-result counting

```python
                if verifier is not None and domain:
                    result = await verifier.verify(domain)
                    alert["verification"] = result.to_dict()
                    stats.record_verification(result.status)
```

Phase 7 already attached verification results to alerts.

Phase 8 now also counts those statuses for the interval summary.

This makes the summary stream more useful because you can see not just that alerts fired, but also whether they were matching trusted answers, confirmed divergent, or verification failed.

---

### Alert counting and logging

```python
                stats.record_alert()
                log_alert(alert)
```

This is the main logging handoff:

- count the alert in the interval stats
- emit it through the dedicated JSON logger

That keeps alert output formatting centralized in `logger.py`.

---

### Summary-task cleanup

```python
    finally:
        summary_task.cancel()
        try:
            await summary_task
        except asyncio.CancelledError:
            pass
```

When the detector shuts down, the summary task is cancelled cleanly.

This avoids leaving a dangling background task around and suppresses the expected `CancelledError`.

---

## `tests/test_logger.py`

This file provides local validation for the new JSON logger and the interval-stats helper.

---

### Imports and path setup

```python
import io
import json
import sys

sys.path.insert(0, "detector/src")
```

These imports support:

- capturing stdout in memory
- parsing emitted JSON
- importing the repo-local logger module directly

---

### Logger imports

```python
from logger import SummaryStats, log_alert, log_summary
```

The tests focus exactly on the new Phase 8 components.

---

### Test: alert logger

```python
def test_log_alert_emits_json_with_logged_at() -> None:
```

This captures stdout while `log_alert()` runs and then parses the emitted line as JSON.

It verifies:

- the original alert fields are preserved
- `logged_at` is added

This is the smallest unit test for the alert-output path.

---

### Test: summary logger

```python
def test_log_summary_emits_json_with_type_and_logged_at() -> None:
```

This performs the same style of test for summary output.

It verifies:

- the summary remains valid JSON
- `type == "summary"` is preserved
- `logged_at` is added

That helps ensure alerts and summaries share the same JSON-lines output style.

---

### Test: stats snapshot resets interval counts

```python
def test_summary_stats_snapshot_resets_interval_counts() -> None:
```

This checks the most important behavior of `SummaryStats`:

1. counters accumulate events, alerts, and verification results
2. `snapshot()` returns the correct summary object
3. the counters reset after the snapshot

That is what makes periodic interval summaries meaningful rather than cumulative forever.

---

## Output Logic Summary

Phase 8's output path can be summarized as:

```python
for each event:
    count event
    run heuristics
    for each alert:
        standardize domain field
        attach verification if enabled
        count alert
        count verification result
        log_alert(alert)

every N seconds:
    log_summary(current_interval_stats)
    reset interval counters
```

This produces a clean, structured output stream with two JSON object types:

- alerts
- summaries

Both are line-delimited and easy to parse.

---

## Why Add a Shared `domain` Field?

Before Phase 8, each heuristic used slightly different naming:

- `domain`
- `target_domain`
- `query_domain`

That is fine for internal logic, but awkward for downstream analysis.

By ensuring every emitted alert also has a common `domain` field, Phase 8 gives consumers one stable place to look.

That makes:

- filtering
- indexing
- aggregation
- alert correlation

much simpler.

---

## Why Emit Summaries Even During Quiet Periods?

If a detector only prints when something bad happens, silence is ambiguous:

- maybe the detector is healthy and traffic is normal
- maybe the detector is hung
- maybe ingestion broke

Periodic summary logs solve that ambiguity.

Even when there are zero alerts, the summary can still show:

- events are being processed
- the detector is alive
- query matching is active
- verification has or has not been running

That is extremely useful during long normal-traffic baselines.

---

## What Phase 8 Does Not Do Yet

Phase 8 improves structured output, but it still does not:

- write logs to files directly
- provide long-term persistence or rotation
- emit lifetime totals alongside interval totals
- expose Prometheus-style metrics
- add richer summary breakdowns by heuristic type

Those are later observability improvements.

Phase 8's job is to make stdout clean, structured, and operationally informative.

---

## What Changed From Phase 7

Phase 7 enriched alerts with active verification results.

Phase 8 improves how that information is emitted and monitored:

- alerts are logged through a dedicated JSON logger
- all alerts get a normalized `domain` field
- periodic summaries show detector health and workload

That makes the project much easier to operate, demo, and analyze during long runs.
