# Phase 3 Explained — Line by Line

This document walks through every file created or modified in Phase 3 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

Phase 2 gave the detector a stream of structured `DNSEvent` objects from Unbound's dnstap output. Phase 3 adds the first real detection logic: track in-flight resolver queries, match responses against them, and raise alerts when a response arrives that does not fit expected resolver behavior.

```
Unbound dnstap ───► ingest_dnstap.py ───► DNSEvent ───► QueryResponseMatcher
                                                     ├── pending query store
                                                     ├── timeout cleanup
                                                     ├── unsolicited detection
                                                     └── duplicate detection
                                                               │
                                                               ▼
                                                         JSON alerts to stdout
```

The logic is intentionally simple:

1. When Unbound sends a `resolver_query`, store it as pending.
2. When a `resolver_response` arrives, look for a matching pending query.
3. If no match exists, the response is **unsolicited**.
4. If one matching response already arrived and another appears shortly after, it is a **duplicate response**.

This is the first phase where the detector stops being just a telemetry pipeline and starts acting like a security system.

---

## Files Added or Modified in Phase 3

Phase 3 touched these files:

- `detector/src/heuristics/__init__.py`
- `detector/src/heuristics/query_response.py`
- `detector/src/main.py`
- `tests/test_query_response.py`

No new Python dependencies were added in this phase. The Phase 2 event model (`DNSEvent`) and ingestion pipeline stay the same; Phase 3 builds detection on top of them.

---

## `detector/src/heuristics/__init__.py`

```python
"""Detection heuristics for DNShield."""
```

This file marks `heuristics/` as a Python package. That allows imports like:

```python
from heuristics.query_response import QueryResponseMatcher
```

There is no runtime logic here. It just gives the directory package semantics.

---

## `detector/src/heuristics/query_response.py`

This is the main Phase 3 file. It contains all query-response matching logic.

### Imports and type alias

```python
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from models import DNSEvent
```

- `dataclass` is used for the small internal state object `PendingQuery`.
- `datetime` and `timedelta` are needed for query expiry and duplicate-response grace windows.
- `Optional` means a field may be a `DNSEvent` or `None`.
- `DNSEvent` is the structured event model from Phase 2.

```python
Alert = dict[str, object]
```

This is a type alias for alert payloads emitted by the matcher.

Instead of returning raw strings or tuples, the matcher returns structured dictionaries that can be directly JSON-serialized by `main.py`.

---

### Internal state object

```python
@dataclass
class PendingQuery:
    query_event: DNSEvent
    first_response: Optional[DNSEvent] = None
    first_response_at: Optional[datetime] = None
    duplicate_alerted: bool = False
```

This stores the lifecycle of one in-flight resolver query.

- `query_event` is the original outgoing resolver query.
- `first_response` stores the first valid matching response we saw.
- `first_response_at` records when that first response arrived.
- `duplicate_alerted` prevents alert spam if multiple duplicate packets arrive.

Why keep the first response instead of immediately deleting the query from the store? Because Phase 3 wants duplicate-response detection. If we removed the entry right away, the second response would look unsolicited instead of duplicate.

---

### Matcher class

```python
class QueryResponseMatcher:
```

This class owns the pending-query dictionary and all matching logic.

Using a class instead of module-level globals keeps the state isolated and testable.

---

### Constructor

```python
def __init__(
    self,
    query_timeout_seconds: int = 10,
    duplicate_grace_seconds: int = 2,
) -> None:
```

Two time windows are configurable:

- `query_timeout_seconds`: how long to keep a query pending before giving up.
- `duplicate_grace_seconds`: how long to keep the first response around in case a second one arrives.

These defaults match the implementation plan closely.

```python
    self.query_timeout = timedelta(seconds=query_timeout_seconds)
    self.duplicate_grace = timedelta(seconds=duplicate_grace_seconds)
    self.pending_queries: dict[tuple[str, str, int, int], PendingQuery] = {}
```

- `timedelta` makes time comparisons straightforward.
- `pending_queries` is the in-memory store.

The dictionary key is:

```python
(query_name, query_type, transaction_id, source_port)
```

This is a strong enough tuple to distinguish multiple in-flight resolver queries for the same name.

Why include `source_port`? Because TXID alone is only 16 bits and can collide. The resolver's source port is part of what makes a DNS query unique on the wire.

---

### Main event-processing function

```python
def process_event(self, event: DNSEvent) -> list[Alert]:
```

This is the public API for the heuristic.

It accepts one `DNSEvent` and returns zero or more alerts.

Returning a list instead of a single alert keeps the main loop simple and leaves room for future expansions.

---

### Expiry sweep

```python
    self._sweep_expired(event.timestamp)
```

Before doing anything else, the matcher removes stale entries.

This matters for two reasons:

- it prevents unbounded memory growth
- it ensures old queries do not incorrectly match unrelated future responses

Using the current event's timestamp instead of wall-clock `now()` keeps the behavior deterministic in tests.

---

### Ignore non-resolver traffic

```python
    if not event.message_type.startswith("resolver_"):
        return []
```

Phase 3 only cares about resolver-facing traffic:

- `resolver_query`
- `resolver_response`

It ignores `client_query` and `client_response` because those are between the stub client and Unbound, not between Unbound and upstream authoritative servers.

That distinction matters because poisoning attacks target the resolver's upstream traffic, not the client-facing side.

---

### Handling resolver queries

```python
    if event.event_type == "query":
        self.pending_queries[self._event_key(event)] = PendingQuery(query_event=event)
        return []
```

When the resolver sends a query upstream, we add it to the pending store.

No alert is generated at this point because a query is normal behavior.

The stored value is a `PendingQuery` object so we can later attach the first response and track whether we already alerted on duplicates.

---

### Ignore unknown event types

```python
    if event.event_type != "response":
        return []
```

In practice the ingestion pipeline currently produces only `"query"` and `"response"`, but this guard makes the matcher more robust if future message types appear.

---

### Matching incoming resolver responses

```python
    key = self._event_key(event)
    pending = self.pending_queries.get(key)
```

We compute the same tuple key for the response and look it up in the pending-query store.

If a response matches a known pending query, it is expected traffic.

If no match exists, it is suspicious.

---

### Unsolicited response detection

```python
    if pending is None:
        return [self._unsolicited_alert(event)]
```

This is the first Phase 3 detection path.

If a resolver response arrives for a query tuple that is not currently pending, the detector raises an `unsolicited_response` alert.

That means one of two things happened:

- a spoofed response was injected
- our matching logic missed the query

In healthy normal traffic, this should be rare to nonexistent.

---

### First matching response

```python
    if pending.first_response is None:
        pending.first_response = event
        pending.first_response_at = event.timestamp
        return []
```

The first valid matching response is treated as the expected answer.

We do not alert on it.

We also do not immediately remove the pending entry, because we want a short window to catch a second competing response.

`first_response_at` starts the duplicate-response grace timer.

---

### Duplicate response detection

```python
    if pending.duplicate_alerted:
        return []
```

If we already flagged a duplicate for this query, do nothing.

This prevents repeated alerts for the third, fourth, or fifth duplicate packet in a flood.

```python
    pending.duplicate_alerted = True
    return [self._duplicate_alert(pending.first_response, event)]
```

If a second response arrives before the grace window expires, the detector emits a `duplicate_response` alert.

The alert includes both the first and second answer sections so you can compare whether the responses actually disagree.

That matters because duplicate traffic could be benign retransmission or a real poisoning attempt. Seeing both answers gives useful context.

---

### Expiry cleanup function

```python
def _sweep_expired(self, now: datetime) -> None:
```

This function removes old entries from `pending_queries`.

It handles two cases:

1. queries that never received any response
2. queries that already received a first response and have outlived the duplicate window

```python
    expired_keys = []
    for key, pending in self.pending_queries.items():
```

We collect expired keys first instead of deleting while iterating, because mutating a dictionary during iteration raises an error.

```python
        if pending.first_response_at is not None:
            if now - pending.first_response_at > self.duplicate_grace:
                expired_keys.append(key)
```

If a query already received a first response, keep it only for the duplicate grace period.

After that, it is no longer useful and can be removed.

```python
        elif now - pending.query_event.timestamp > self.query_timeout:
            expired_keys.append(key)
```

If a query never got any response and has been pending too long, remove it.

Otherwise the store would grow forever under packet loss or malformed traffic.

```python
    for key in expired_keys:
        self.pending_queries.pop(key, None)
```

Actually remove the expired entries.

`pop(key, None)` avoids raising an error if something else already removed the key.

---

### Query tuple helper

```python
@staticmethod
def _event_key(event: DNSEvent) -> tuple[str, str, int, int]:
```

This helper centralizes how we define "the same query".

```python
    return (
        event.query_name.lower(),
        event.query_type.upper(),
        event.transaction_id,
        event.source_port,
    )
```

Normalization matters:

- domain names are lowercased because DNS names are case-insensitive
- query types are uppercased for consistency

Using a shared helper prevents subtle mismatches between query-side and response-side key generation.

---

### Unsolicited alert payload

```python
@staticmethod
def _unsolicited_alert(event: DNSEvent) -> Alert:
```

This creates the JSON-ready payload for unsolicited responses.

```python
    return {
        "alert_type": "unsolicited_response",
        "severity": "HIGH",
        "domain": event.query_name,
        "query_type": event.query_type,
        "txid": event.transaction_id,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "timestamp": event.timestamp.isoformat(),
    }
```

Field meanings:

- `alert_type`: what kind of detection fired
- `severity`: a coarse priority label
- `domain`, `query_type`, `txid`: identify the suspicious response
- `source_ip`, `source_port`: where the response appears to have come from
- `timestamp`: when the response arrived

`isoformat()` converts the datetime to a JSON-safe string.

---

### Duplicate alert payload

```python
@staticmethod
def _duplicate_alert(first_response: DNSEvent, second_response: DNSEvent) -> Alert:
```

This creates the JSON-ready payload for duplicate responses.

```python
    return {
        "alert_type": "duplicate_response",
        "severity": "HIGH",
        "domain": second_response.query_name,
        "query_type": second_response.query_type,
        "txid": second_response.transaction_id,
        "first_answer": first_response.answers,
        "second_answer": second_response.answers,
        "timestamp": second_response.timestamp.isoformat(),
    }
```

This alert includes both answer sets, which is the most important context for duplicate-response analysis.

If the answers differ, that is much more suspicious than two identical copies.

---

## `detector/src/main.py`

Phase 2 printed every ingested event. Phase 3 changes `main.py` into a detection loop.

### New import

```python
from heuristics.query_response import QueryResponseMatcher
```

This imports the Phase 3 heuristic.

The ingestion pipeline stays the same; only the consumer logic changes.

---

### Matcher creation

```python
matcher = QueryResponseMatcher()
```

The detector creates one matcher instance and keeps it alive for the lifetime of the process.

That instance owns all in-memory pending-query state.

If we recreated it on every event, the detector would forget previous queries and could never match responses correctly.

---

### Main loop

```python
async for event in ingest_events(SOCKET_PATH):
```

This still consumes the async dnstap event stream from Phase 2.

The architecture remains modular:

- Phase 2 handles ingestion
- Phase 3 handles detection

That separation is exactly why Phase 2 used `DNSEvent` objects instead of baking logic directly into the parser.

---

### Running the heuristic

```python
    alerts = matcher.process_event(event)
```

Each incoming event is fed into the matcher.

The matcher updates its internal state and returns any alerts generated by that event.

This is a push-based model: the heuristic decides whether the new event changes anything meaningful.

---

### Printing alerts

```python
    for alert in alerts:
        print(json.dumps(alert), flush=True)
```

Phase 3 now prints only alerts, not all raw events.

That is an intentional shift:

- Phase 2 was about visibility into the event stream
- Phase 3 is about surfacing suspicious behavior

`flush=True` keeps alerts visible immediately in Docker logs.

Later phases can keep stacking more heuristics into this loop.

---

## `tests/test_query_response.py`

This file provides local validation for the matcher logic without requiring Docker or live dnstap traffic.

### Imports and path setup

```python
from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, "detector/src")
```

The test file inserts `detector/src` into Python's import path so it can import the heuristic and model modules directly from the repo layout.

This is a lightweight local-testing setup.

---

### Test imports

```python
from heuristics.query_response import QueryResponseMatcher
from models import DNSEvent
```

These are the two Phase 3 pieces the tests exercise:

- the matcher implementation
- the shared event model

---

### Event factory helper

```python
def make_event(... ) -> DNSEvent:
```

This helper creates synthetic `DNSEvent` objects for tests.

It keeps the test bodies short and readable by hiding repetitive event construction.

```python
    return DNSEvent(
        timestamp=timestamp,
        event_type=event_type,
        message_type=message_type,
        query_name=query_name,
        query_type=query_type,
        transaction_id=transaction_id,
        source_ip=source_ip,
        source_port=source_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        response_code=response_code,
        answers=answers or [],
    )
```

Only the fields relevant to Phase 3 are varied in most tests.

The rest get sensible defaults.

That keeps each test focused on behavior rather than setup noise.

---

### Test: normal query/response pair

```python
def test_normal_query_then_response_has_no_alerts_and_expires() -> None:
```

This verifies the happy path.

A normal resolver query followed by its first response should not generate any alert.

```python
    assert matcher.process_event(query) == []
    assert matcher.process_event(response) == []
```

No alerts on normal traffic.

```python
    assert len(matcher.pending_queries) == 1
```

After the first response, the query is still retained temporarily for duplicate detection.

```python
    matcher.process_event(cleanup_probe)
    assert matcher.pending_queries == {}
```

A later event advances time and triggers cleanup. The old entry disappears after the grace window.

This confirms the detector does not leak memory indefinitely.

---

### Test: unsolicited response

```python
def test_unsolicited_response_triggers_alert() -> None:
```

This sends a response event without any prior matching query.

```python
    alerts = matcher.process_event(response)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "unsolicited_response"
```

That verifies the first major Phase 3 detection path.

---

### Test: duplicate response

```python
def test_duplicate_response_triggers_single_alert() -> None:
```

This simulates:

1. one normal query
2. one valid first response
3. one second competing response shortly after

```python
    alerts = matcher.process_event(second_response)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "duplicate_response"
```

That verifies the duplicate-detection path.

```python
    assert alerts[0]["first_answer"] == [...]
    assert alerts[0]["second_answer"] == [...]
```

This specifically checks that the alert preserves both answers.

That is important for debugging and incident analysis.

```python
    assert matcher.process_event(second_response) == []
```

If the same duplicate keeps arriving, the matcher should not keep re-alerting forever. This confirms the anti-spam guard.

---

### Test: stale pending query cleanup

```python
def test_stale_pending_query_is_removed_after_timeout() -> None:
```

This checks the other cleanup path: a query that never got a response.

```python
    matcher.process_event(query)
    assert len(matcher.pending_queries) == 1
```

The pending store should contain the query initially.

```python
    matcher.process_event(late_probe)
    assert matcher.pending_queries == {}
```

A later event advances time beyond the timeout, and the stale query is removed.

This verifies the timeout logic works even without a real response.

---

## Detection Logic Summary

Phase 3's logic can be summarized as:

```python
for event in dnstap_stream:
    expire_old_queries()

    if event is resolver_query:
        pending[key] = query

    elif event is resolver_response:
        if key not in pending:
            alert("unsolicited_response")
        elif first response not seen yet:
            store first response
        elif duplicate alert not sent yet:
            alert("duplicate_response")
```

This is intentionally simple. The goal is not to perfectly classify every unusual DNS edge case yet. The goal is to build a strong first detector for "responses that do not line up with expected resolver behavior".

---

## Why Keep a Grace Window?

The short grace window after the first response is what makes duplicate detection possible.

If we removed a pending query immediately after the first response:

- the second response would arrive
- there would be no pending entry
- it would be labeled unsolicited instead of duplicate

That would lose useful context. Duplicate detection is stronger because it tells us:

- the resolver really did ask the question
- one response already arrived
- now a second competing response is showing up

That is much closer to the shape of a spoofing race.

---

## Why Only `resolver_*` Events?

Phase 3 ignores `client_query` and `client_response` on purpose.

The threat model here is upstream poisoning:

- Unbound asks an authoritative server something
- an attacker races a spoofed answer back

That attack happens on the resolver-facing side, so `resolver_query` and `resolver_response` are the right signals.

Client-facing events are still useful later, but they are not the right matching layer for this heuristic.

---

## What Phase 3 Does Not Do Yet

Phase 3 is intentionally narrow. It does not yet:

- detect random-subdomain floods
- examine bailiwick violations
- compare answers against outside resolvers
- distinguish benign retransmissions from malicious duplicates
- persist alerts anywhere besides stdout

Those come in later phases. Phase 3's job is to establish a clean pending-query tracker and the first two high-value alerts.

---

## What Changed From Phase 2

Phase 2 was passive ingestion: parse and print events.

Phase 3 is active detection: maintain state across events and only print alerts when suspicious patterns appear.

That is the first real transition from "telemetry pipeline" to "security detector".
