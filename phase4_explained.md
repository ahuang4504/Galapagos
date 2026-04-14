# Phase 4 Explained — Line by Line

This document walks through every file created or modified in Phase 4 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

Phase 3 introduced stateful matching for resolver queries and responses. Phase 4 adds a second heuristic aimed at the setup stage of a Kaminsky-style cache poisoning attack: a burst of many unique random subdomains beneath the same parent domain.

```
Unbound dnstap ───► ingest_dnstap.py ───► DNSEvent ───► main.py
                                                     ├── QueryResponseMatcher
                                                     └── KaminskyPrecursorDetector
                                                           ├── parent-domain extraction
                                                           ├── sliding window tracker
                                                           ├── alert threshold
                                                           └── per-domain cooldown
                                                                     │
                                                                     ▼
                                                               JSON alerts to stdout
```

The idea behind the heuristic is:

1. Watch resolver-side query traffic.
2. Group queries by parent domain, such as `example.com`.
3. Count how many unique full subdomains appear inside a short time window.
4. If that count gets unusually high, emit a `kaminsky_precursor` alert.

The attack signal is not "one weird DNS query". It is "a resolver suddenly asking for many never-before-seen names like `a1.example.com`, `a2.example.com`, `a3.example.com`, all under the same parent domain". That is exactly the pattern this phase tries to capture.

---

## Files Added or Modified in Phase 4

Phase 4 touched these files:

- `detector/src/heuristics/kaminsky_precursor.py`
- `detector/src/main.py`
- `tests/test_kaminsky_precursor.py`

Phase 3's files remain in place. Phase 4 adds a second heuristic module and wires it into the same main event loop.

---

## `detector/src/heuristics/kaminsky_precursor.py`

This is the main Phase 4 file. It contains the parent-domain helper and the sliding-window detector.

### Imports

```python
from datetime import datetime, timedelta

from models import DNSEvent
```

- `datetime` is used for per-domain window start times and cooldown timestamps.
- `timedelta` represents the window duration and cooldown duration.
- `DNSEvent` is the event model from Phase 2 that the detector consumes.

There is no dataclass here because the state is simple enough to keep in plain dictionaries.

---

### Alert type alias

```python
Alert = dict[str, object]
```

Like Phase 3, the detector emits alert dictionaries that are already JSON-ready.

That keeps the interface between heuristics and `main.py` consistent: every heuristic accepts a `DNSEvent` and returns a list of alert dictionaries.

---

### Parent-domain extraction helper

```python
def extract_parent_domain(query_name: str) -> str:
```

This helper reduces a full query name like `abc123.bankofamerica.com` to the parent domain `bankofamerica.com`.

The detector uses the parent domain as the grouping key for the sliding window.

```python
    normalized = query_name.rstrip(".").lower()
```

This normalizes the incoming name:

- `.rstrip(".")` removes the trailing DNS root dot if present
- `.lower()` normalizes case because DNS names are case-insensitive

Without this normalization, `Example.COM.` and `example.com` would be treated as different domains.

```python
    labels = [label for label in normalized.split(".") if label]
```

This splits the domain into labels and drops any empty pieces.

For example:

- `a.b.example.com` becomes `["a", "b", "example", "com"]`
- `example.com` becomes `["example", "com"]`

```python
    if len(labels) <= 2:
        return normalized
```

If the query is already a bare domain like `google.com`, return it unchanged.

This matches the simplification from the implementation plan: for the project, the parent domain is approximated as the last two labels.

```python
    return ".".join(labels[-2:])
```

For deeper names, return the last two labels:

- `a.b.c.example.com` becomes `example.com`
- `abc123.bankofamerica.com` becomes `bankofamerica.com`

This is not a full Public Suffix List implementation. It is a project-friendly simplification.

---

### Detector class

```python
class KaminskyPrecursorDetector:
```

This class owns all state for the precursor heuristic.

It tracks:

- unique subdomains seen in the current window
- when the current window started
- when the last alert fired for a parent domain

Keeping it in a class makes it easy to hold state across events and easy to test in isolation.

---

### Constructor

```python
def __init__(
    self,
    threshold: int = 20,
    window_seconds: int = 30,
    cooldown_seconds: int = 60,
) -> None:
```

These three parameters define the behavior of the heuristic:

- `threshold`: how many unique subdomains must appear before alerting
- `window_seconds`: how wide the counting window is
- `cooldown_seconds`: how long to suppress repeat alerts for the same parent domain

The defaults match the Phase 4 plan closely.

```python
    self.threshold = threshold
    self.window = timedelta(seconds=window_seconds)
    self.cooldown = timedelta(seconds=cooldown_seconds)
```

- `threshold` stays as an integer count
- `window` and `cooldown` are converted to `timedelta` for easy timestamp arithmetic

```python
    self.subdomain_tracker: dict[str, set[str]] = {}
    self.window_start: dict[str, datetime] = {}
    self.last_alert_time: dict[str, datetime] = {}
```

These are the core data structures:

- `subdomain_tracker[parent]` stores the set of unique full query names seen in the current window
- `window_start[parent]` stores when that parent's current counting window began
- `last_alert_time[parent]` stores when the last alert fired, so we can suppress repeated alerts during sustained floods

Using a `set[str]` is important because we care about unique subdomains, not just raw request volume. Ten repeated queries for the same name should not look like ten distinct random subdomains.

---

### Main event-processing function

```python
def process_event(self, event: DNSEvent) -> list[Alert]:
```

This is the public API for the heuristic.

It accepts one `DNSEvent` and returns zero or more alerts.

The signature matches Phase 3's matcher so both heuristics can be called from the same loop.

---

### Ignore irrelevant traffic

```python
    if event.message_type != "resolver_query" or event.event_type != "query":
        return []
```

Phase 4 only cares about outgoing resolver queries.

Why?

- Kaminsky precursor behavior is visible in the resolver's upstream queries
- client-facing traffic does not show the same signal clearly
- responses are not what this heuristic counts

So the detector only processes `resolver_query` events with `event_type == "query"`.

---

### Parent-domain lookup

```python
    parent_domain = extract_parent_domain(event.query_name)
    if not parent_domain:
        return []
```

The detector groups activity by the parent domain.

If the helper returns an empty string, the event is ignored. In practice that should be rare, but the guard keeps the code safe against malformed input.

---

### Window reset check

```python
    self._reset_window_if_needed(parent_domain, event.timestamp)
```

Before counting the current query, the detector checks whether the old counting window has expired.

If enough time has passed since the window started, the old set of subdomains is discarded and a fresh window begins.

This keeps the heuristic focused on bursts, not on long-term history.

---

### First event for a parent domain

```python
    if parent_domain not in self.subdomain_tracker:
        self.subdomain_tracker[parent_domain] = set()
        self.window_start[parent_domain] = event.timestamp
```

If this is the first time we have seen this parent domain, create:

- an empty set to track unique subdomains
- a window start timestamp

The window starts with the first event, not with process startup.

---

### Add the query to the set

```python
    self.subdomain_tracker[parent_domain].add(event.query_name.lower().rstrip("."))
    unique_count = len(self.subdomain_tracker[parent_domain])
```

This records the full query name, not just the parent domain.

That matters because the heuristic is counting how many distinct names appear under the same parent:

- `a1.example.com`
- `a2.example.com`
- `a3.example.com`

All of those share `example.com` as the parent, but each full name is distinct.

Using a set automatically removes duplicates, so repeated queries for the exact same subdomain do not inflate the count.

---

### Threshold check

```python
    if unique_count <= self.threshold:
        return []
```

No alert is emitted until the number of unique names exceeds the threshold.

The use of `<=` means the alert fires only when the count becomes strictly greater than the threshold.

So with a threshold of `20`:

- counts `1..20` do not alert
- count `21` is the first alerting point

This avoids flagging ordinary low-volume subdomain lookups.

---

### Cooldown check

```python
    last_alert = self.last_alert_time.get(parent_domain)
    if last_alert is not None and event.timestamp - last_alert <= self.cooldown:
        return []
```

Once an alert fires for a parent domain, suppress repeated alerts for that same parent during the cooldown period.

Without this, a sustained random-subdomain flood could produce an alert on every new query after the threshold, which would quickly become noisy.

The cooldown is tracked per parent domain, not globally. That means a flood against `example.com` does not suppress alerts for `bankofamerica.com`.

---

### Record alert time and emit alert

```python
    self.last_alert_time[parent_domain] = event.timestamp
    return [self._build_alert(parent_domain, event.timestamp)]
```

If the threshold is exceeded and the cooldown allows it:

1. store the alert timestamp
2. build and return a `kaminsky_precursor` alert

Only one alert is emitted per triggering event.

---

### Window-reset helper

```python
def _reset_window_if_needed(self, parent_domain: str, now: datetime) -> None:
```

This helper checks whether the current window for a parent domain has expired.

```python
    started_at = self.window_start.get(parent_domain)
    if started_at is None:
        return
```

If the parent domain has never been seen before, there is no window to reset.

```python
    if now - started_at > self.window:
        self.subdomain_tracker[parent_domain] = set()
        self.window_start[parent_domain] = now
```

If enough time has passed since the window started:

- clear the set of subdomains
- begin a new window at the current event time

This makes the heuristic a true sliding-window approximation over recent traffic instead of a forever-growing counter.

---

### Alert builder

```python
def _build_alert(self, parent_domain: str, timestamp: datetime) -> Alert:
```

This creates the JSON-ready alert payload.

```python
    subdomains = sorted(self.subdomain_tracker[parent_domain])
```

The set is converted to a sorted list so the output is deterministic and easier to read in logs and tests.

```python
    return {
        "alert_type": "kaminsky_precursor",
        "severity": "CRITICAL",
        "target_domain": parent_domain,
        "unique_subdomains_count": len(subdomains),
        "window_seconds": int(self.window.total_seconds()),
        "sample_subdomains": subdomains[:5],
        "timestamp": timestamp.isoformat(),
    }
```

Field meanings:

- `alert_type`: identifies the heuristic
- `severity`: marks this as high-priority suspicious behavior
- `target_domain`: the parent domain under attack
- `unique_subdomains_count`: how many distinct names were seen in the current window
- `window_seconds`: the configured window size
- `sample_subdomains`: a few example names that triggered the alert
- `timestamp`: when the alert fired

Only the first five subdomains are included to keep alert payloads compact.

---

## `detector/src/main.py`

Phase 4 reuses the same event loop from Phase 3 and adds a second heuristic into it.

### New import

```python
from heuristics.kaminsky_precursor import KaminskyPrecursorDetector
```

This imports the Phase 4 heuristic.

The query-response matcher from Phase 3 remains in place, so the detector now runs two heuristics in parallel over the same event stream.

---

### Detector creation

```python
precursor = KaminskyPrecursorDetector()
```

The detector creates one `KaminskyPrecursorDetector` instance at startup and keeps it alive for the lifetime of the process.

That instance owns all sliding-window state across events.

---

### Combining alerts from both heuristics

```python
    alerts = matcher.process_event(event)
    alerts.extend(precursor.process_event(event))
```

Each event is passed through both heuristics:

- `QueryResponseMatcher` for unsolicited and duplicate responses
- `KaminskyPrecursorDetector` for random-subdomain bursts

Both return lists of alert dictionaries, and `extend()` appends Phase 4 alerts into the same list.

This keeps the main loop simple while allowing multiple heuristics to coexist cleanly.

---

### Printing alerts

```python
    for alert in alerts:
        print(json.dumps(alert), flush=True)
```

This stays the same as Phase 3.

The important architectural point is that `main.py` does not care which heuristic produced an alert. It simply serializes whatever alert dictionaries it receives.

That makes the detector easy to expand in later phases.

---

## `tests/test_kaminsky_precursor.py`

This file provides local validation for the Phase 4 heuristic without requiring Docker or live attack traffic.

### Imports and path setup

```python
from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, "detector/src")
```

This mirrors the Phase 3 test setup and lets the tests import the detector modules directly from the repo.

---

### Test imports

```python
from heuristics.kaminsky_precursor import (
    KaminskyPrecursorDetector,
    extract_parent_domain,
)
from models import DNSEvent
```

These are the exact Phase 4 pieces under test:

- the parent-domain helper
- the precursor detector class
- the shared event model

---

### Event factory helper

```python
def make_event(... ) -> DNSEvent:
```

This helper creates synthetic query events for tests.

It keeps the test bodies readable by centralizing repeated `DNSEvent` construction.

```python
    return DNSEvent(
        timestamp=timestamp,
        event_type=event_type,
        message_type=message_type,
        query_name=query_name,
        query_type="A",
        transaction_id=1234,
        source_ip="172.28.0.10",
        source_port=5300,
        dest_ip="198.41.0.4",
        dest_port=53,
    )
```

Most fields are fixed defaults because Phase 4 only really cares about:

- timestamp
- query name
- message type
- event type

The rest are still populated so the object is a valid `DNSEvent`.

---

### Test: parent-domain extraction

```python
def test_extract_parent_domain_examples() -> None:
```

This verifies the helper on the main planned examples:

- bare domain
- random subdomain
- deep subdomain
- trailing-dot normalization

```python
    assert extract_parent_domain("google.com") == "google.com"
    assert extract_parent_domain("abc123.bankofamerica.com") == "bankofamerica.com"
    assert extract_parent_domain("a.b.c.d.example.com") == "example.com"
    assert extract_parent_domain("example.com.") == "example.com"
```

That confirms the normalization and last-two-label behavior.

---

### Test: normal traffic stays quiet

```python
def test_normal_traffic_does_not_trigger_alert() -> None:
```

This simulates a small mix of ordinary subdomain lookups spread across a couple parent domains.

```python
    alerts = []
    for event in events:
        alerts.extend(detector.process_event(event))

    assert alerts == []
```

The expectation is that normal browsing-like traffic should not exceed the threshold and should not trigger a precursor alert.

---

### Test: threshold crossing triggers alert

```python
def test_threshold_crossing_triggers_alert() -> None:
```

This sends multiple unique subdomains under the same parent domain within one window.

```python
    for idx in range(4):
        event = make_event(
            timestamp=now + timedelta(seconds=idx),
            query_name=f"rand{idx}.example.com",
        )
```

Each query is distinct, so the set of unique names grows.

```python
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "kaminsky_precursor"
    assert alerts[0]["target_domain"] == "example.com"
    assert alerts[0]["unique_subdomains_count"] == 4
```

This confirms the core detection path.

---

### Test: cooldown suppresses repeat alerts

```python
def test_cooldown_suppresses_repeat_alerts() -> None:
```

This simulates two bursts against the same parent domain while still inside the cooldown period.

The first burst should alert. The second should not.

```python
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "kaminsky_precursor"
```

That verifies the anti-spam behavior.

---

### Test: new window can alert again later

```python
def test_new_window_after_expiry_can_alert_again() -> None:
```

This verifies that alerts are not permanently suppressed forever.

If both the counting window and the cooldown have expired, a new burst under the same parent domain should be able to trigger a fresh alert.

```python
    assert len(alerts) == 2
    assert alerts[0]["target_domain"] == "example.com"
    assert alerts[1]["target_domain"] == "example.com"
```

That confirms the detector resets and can fire again for future suspicious activity.

---

### Test: non-resolver traffic is ignored

```python
def test_non_resolver_queries_are_ignored() -> None:
```

This ensures the detector ignores:

- client-facing queries
- response events

```python
    assert detector.process_event(client_event) == []
    assert detector.process_event(response_event) == []
```

That keeps the heuristic aligned with its threat model and avoids counting irrelevant traffic.

---

## Detection Logic Summary

Phase 4's logic can be summarized as:

```python
for event in dnstap_stream:
    if event is not resolver_query:
        continue

    parent = extract_parent_domain(event.query_name)
    reset_window_if_expired(parent)
    subdomain_set[parent].add(event.query_name)

    if len(subdomain_set[parent]) > threshold:
        if parent not in cooldown:
            alert("kaminsky_precursor")
```

This is intentionally heuristic rather than perfect. The goal is not to prove an attack has succeeded. The goal is to flag the suspicious precursor pattern that typically appears before a Kaminsky poisoning attempt wins the race.

---

## Why Count Unique Subdomains?

The Kaminsky attack pattern relies on generating many cache misses by querying random names that the resolver has never seen before:

- `x1.example.com`
- `x2.example.com`
- `x3.example.com`

If the detector counted total query volume instead of unique names, repeated retries for one subdomain could look like an attack. Using a set of full query names focuses the heuristic on novelty, which is the more relevant signal here.

---

## Why Group by Parent Domain?

The attack targets a specific parent domain, not the random labels themselves.

The random prefixes change every time, but the parent domain stays constant:

- `aaa.example.com`
- `bbb.example.com`
- `ccc.example.com`

All three are really part of one campaign against `example.com`.

That is why the window is keyed by parent domain.

---

## Why Add a Cooldown?

Once a threshold-crossing burst starts, every additional unique query could otherwise trigger another alert.

That would quickly flood stdout and make the detector hard to use.

The cooldown keeps the heuristic informative instead of noisy:

- first suspicious burst: alert
- continued flood during cooldown: stay quiet
- later suspicious burst after cooldown: alert again

---

## What Phase 4 Does Not Do Yet

Phase 4 is still only a passive heuristic. It does not yet:

- verify suspicious answers against outside resolvers
- inspect authority/additional sections for bailiwick violations
- correlate precursor alerts with subsequent poisoning success
- distinguish an attack burst from every legitimate high-cardinality subdomain workload
- persist alert history anywhere besides stdout

Those come later. Phase 4's job is to spot the classic random-subdomain spray that often precedes a cache poisoning race.

---

## What Changed From Phase 3

Phase 3 tracked one query at a time and reasoned about matching responses.

Phase 4 adds a population-level view: not "did this response match?" but "is this resolver suddenly generating an unusual burst of unique names for one parent domain?"

That makes the detector more useful earlier in an attack timeline. Phase 3 notices suspicious responses. Phase 4 notices the precursor behavior that often sets those responses up.
