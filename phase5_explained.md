# Phase 5 Explained — Line by Line

This document walks through every file created or modified in Phase 5 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

Phase 5 adds a third passive heuristic: bailiwick enforcement. Instead of watching query timing patterns like Phase 3 and Phase 4, this heuristic inspects the contents of DNS response sections and asks a structural question:

"Do the authority and additional records belong to the zone this response is supposed to be about?"

```
Unbound dnstap ───► ingest_dnstap.py ───► DNSEvent ───► main.py
                                                     ├── QueryResponseMatcher
                                                     ├── KaminskyPrecursorDetector
                                                     └── BailiwickEnforcer
                                                           ├── zone extraction
                                                           ├── authority/additional scan
                                                           ├── in-bailiwick checks
                                                           └── violation alerts
                                                                     │
                                                                     ▼
                                                               JSON alerts to stdout
```

The simplified idea is:

1. When a resolver response arrives, derive the expected bailiwick zone from the original query name.
2. Inspect every record in the authority and additional sections.
3. If a record name, or a domain target inside its RDATA, falls outside that zone, flag it.

This is designed to catch forged referral-style records like:

- an NS record pointing `example.com` at `ns1.attacker.net`
- a glue A record for `bankofamerica.com` inside a response about `example.com`

Those are classic signs of a cache-poisoning attempt.

---

## Files Added or Modified in Phase 5

Phase 5 touched these files:

- `detector/src/heuristics/bailiwick.py`
- `detector/src/main.py`
- `tests/test_bailiwick.py`

Phase 5 keeps the Phase 3 and Phase 4 heuristics intact and adds a third heuristic into the same main detector loop.

---

## `detector/src/heuristics/bailiwick.py`

This is the main Phase 5 file. It contains:

- a helper to derive the expected bailiwick zone from the query name
- a helper to decide whether a name is inside a zone
- the `BailiwickEnforcer` heuristic class

---

### Imports

```python
from models import DNSEvent
```

Phase 5 does not need any external libraries beyond the shared event model.

The heuristic works entirely on fields already populated in Phase 2:

- `query_name`
- `authority`
- `additional`
- `timestamp`

---

### Alert type alias

```python
Alert = dict[str, object]
```

Like the other heuristics, Phase 5 returns JSON-ready alert dictionaries.

That keeps the interface uniform across all detectors.

---

### Record-type sets

```python
_RDATA_DOMAIN_TYPES = {"NS", "CNAME", "DNAME", "PTR"}
_RDATA_TRAILING_DOMAIN_TYPES = {"MX", "SRV"}
```

These constants define which record types can contain domain names inside their RDATA.

Why do we need this?

Because bailiwick violations are not limited to the owner name of a record. Sometimes the suspicious name is inside the payload:

- `example.com NS ns1.attacker.net.`

The owner name `example.com` is in-bailiwick, but the target nameserver `ns1.attacker.net` is not. So the heuristic checks both the record name and, for selected record types, the domain target embedded in the RDATA.

The two groups exist because the RDATA format differs:

- `NS`, `CNAME`, `DNAME`, `PTR` usually contain just one domain name
- `MX` and `SRV` include numeric fields before the target domain, so the target appears as the last token

---

### Bailiwick-zone extraction helper

```python
def extract_bailiwick_zone(query_name: str) -> str:
```

This helper derives the expected zone from the query name.

The project uses the same simple approximation as earlier phases: the bailiwick zone is the last two labels of the queried name.

```python
    normalized = _normalize_name(query_name)
    labels = [label for label in normalized.split(".") if label]
```

This first normalizes the input:

- lowercases it
- removes a trailing dot
- strips whitespace

Then it splits the name into labels.

```python
    if len(labels) <= 2:
        return normalized
```

If the query is already a bare domain like `google.com`, return it directly.

```python
    return ".".join(labels[-2:])
```

If the query is deeper, return the last two labels:

- `www.google.com` becomes `google.com`
- `mail.sub.example.org` becomes `example.org`

This is a simplified heuristic rather than a full PSL-based registrable-domain parser, but it is enough for the project.

---

### In-bailiwick helper

```python
def is_in_bailiwick(name: str, zone: str) -> bool:
```

This helper answers the key Phase 5 question:

"Is this name equal to the zone or a subdomain of it?"

```python
    normalized_name = _normalize_name(name)
    normalized_zone = _normalize_name(zone)
```

Normalize both inputs before comparing them so formatting differences do not cause false positives.

```python
    if not normalized_name or not normalized_zone:
        return False
```

If either side is empty, treat the comparison as invalid and return `False`.

This is safer than silently accepting malformed names.

```python
    return (
        normalized_name == normalized_zone
        or normalized_name.endswith(f".{normalized_zone}")
    )
```

This accepts:

- the zone itself, such as `example.com`
- any subdomain beneath it, such as `ns1.example.com`

It rejects unrelated names such as `attacker.net`.

That is the core rule used throughout the rest of the heuristic.

---

### Detector class

```python
class BailiwickEnforcer:
```

This class owns the bailiwick-checking logic.

Unlike Phase 3 and Phase 4, it does not need long-lived state. It simply inspects each response independently and emits alerts if it finds suspicious records.

Keeping it as a class still matches the same heuristic interface as the others and makes future expansion easier.

---

### Main event-processing function

```python
def process_event(self, event: DNSEvent) -> list[Alert]:
```

This is the public API for the heuristic.

It takes one `DNSEvent` and returns zero or more alert dictionaries.

---

### Ignore irrelevant traffic

```python
    if event.message_type != "resolver_response" or event.event_type != "response":
        return []
```

Phase 5 only cares about resolver-side responses.

Why?

- authority and additional sections matter on responses, not queries
- the threat model is upstream poisoning against the recursive resolver
- client-facing traffic is not the right layer for this heuristic

So the enforcer only inspects `resolver_response` events.

---

### Derive the expected zone

```python
    zone = extract_bailiwick_zone(event.query_name)
    if not zone:
        return []
```

The query name tells us what zone the response should be about.

If no valid zone can be derived, the event is ignored rather than guessed.

---

### Scan the authority and additional sections

```python
    alerts = []
    for section_name, records in (
        ("authority", event.authority),
        ("additional", event.additional),
    ):
```

Phase 5 intentionally ignores the answer section and focuses on the parts of the DNS response that are commonly abused in referral poisoning:

- the authority section
- the additional section

Each record tuple comes from Phase 2 in the form:

```python
(name, record_type, ttl, rdata)
```

---

### Per-record inspection

```python
        for name, record_type, ttl, rdata in records:
            violation = self._find_violation(name, record_type, rdata, zone)
            if violation is None:
                continue
```

Each record is inspected individually.

`_find_violation()` decides whether:

- the record owner name is out of bailiwick
- or the record's target name in RDATA is out of bailiwick

If no violation is found, the loop simply continues.

---

### Emit an alert for each violating record

```python
            alerts.append(
                self._build_alert(
                    event=event,
                    zone=zone,
                    section_name=section_name,
                    record_name=name,
                    record_type=record_type,
                    ttl=ttl,
                    rdata=rdata,
                    violation=violation,
                )
            )
```

If a violation is found, the detector emits one alert for that specific record.

This makes the output precise:

- which section contained the bad record
- whether the suspicious part was the owner name or the RDATA target
- which exact record triggered the alert

Returning one alert per bad record is more informative than collapsing everything into a single generic warning.

---

### Violation finder

```python
def _find_violation(
    self,
    record_name: str,
    record_type: str,
    rdata: str,
    zone: str,
) -> dict[str, str] | None:
```

This helper centralizes the actual enforcement logic.

It returns either:

- `None` if the record is acceptable
- a small dictionary describing the violation if the record is suspicious

---

### Check the record owner name

```python
    if not is_in_bailiwick(record_name, zone):
        return {"field": "name", "value": _normalize_name(record_name)}
```

The first check is the simplest one:

"Does the record name itself belong to this zone?"

Example violation:

- query about `www.example.com`
- additional record name `bankofamerica.com`

That should never be legitimate glue or authority information for `example.com`, so the detector flags it immediately.

---

### Check the target embedded in RDATA

```python
    target_name = self._extract_rdata_name(record_type, rdata)
    if target_name and not is_in_bailiwick(target_name, zone):
        return {"field": "rdata", "value": target_name}
```

Some malicious records hide the suspicious domain in the RDATA rather than in the owner name.

Example:

- authority record: `example.com NS ns1.attacker.net.`

Here the owner name `example.com` looks fine, but the nameserver target is not in-bailiwick.

That is why Phase 5 checks both the owner name and, for relevant types, the target embedded in the RDATA.

---

### RDATA-name extraction helper

```python
@staticmethod
def _extract_rdata_name(record_type: str, rdata: str) -> str | None:
```

This helper parses a domain name out of the RDATA string for record types where that makes sense.

```python
    normalized_type = record_type.upper()
    stripped = rdata.strip()
```

Normalize the record type and trim whitespace before inspecting the value.

```python
    if normalized_type in _RDATA_DOMAIN_TYPES:
        return _normalize_name(stripped)
```

For `NS`, `CNAME`, `DNAME`, and `PTR`, the RDATA is effectively a single domain name, so the whole string is normalized and returned.

```python
    if normalized_type in _RDATA_TRAILING_DOMAIN_TYPES:
        parts = stripped.split()
        if parts:
            return _normalize_name(parts[-1])
```

For `MX` and `SRV`, the target domain is the last token:

- `MX`: `10 mail.example.com.`
- `SRV`: `10 5 443 service.example.com.`

So the helper extracts and normalizes just that last token.

```python
    return None
```

For other record types like `A` or `AAAA`, there is no domain target to inspect in the RDATA, so the helper returns `None`.

---

### Alert builder

```python
@staticmethod
def _build_alert(
    *,
    event: DNSEvent,
    zone: str,
    section_name: str,
    record_name: str,
    record_type: str,
    ttl: int,
    rdata: str,
    violation: dict[str, str],
) -> Alert:
```

This creates the JSON-ready alert payload.

```python
    return {
        "alert_type": "bailiwick_violation",
        "severity": "CRITICAL",
        "query_domain": event.query_name,
        "bailiwick_zone": zone,
        "section": section_name,
        "violating_field": violation["field"],
        "violating_value": violation["value"],
        "violating_record": {
            "name": _normalize_name(record_name),
            "type": record_type,
            "ttl": ttl,
            "rdata": rdata,
        },
        "timestamp": event.timestamp.isoformat(),
    }
```

Field meanings:

- `alert_type`: identifies the heuristic
- `severity`: marks this as a critical structural violation
- `query_domain`: the original query name
- `bailiwick_zone`: the expected zone derived from the query
- `section`: whether the bad record was in `authority` or `additional`
- `violating_field`: whether the problem was the record `name` or the `rdata` target
- `violating_value`: the exact out-of-bailiwick name
- `violating_record`: the full offending record
- `timestamp`: when the response was observed

This alert format is richer than the minimal plan because it is useful during debugging and later attack demonstrations.

---

### Name-normalization helper

```python
def _normalize_name(name: str) -> str:
    return name.rstrip(".").lower().strip()
```

This small helper keeps all name comparisons consistent across the file.

It:

- removes a trailing dot
- lowercases the name
- trims whitespace

Having one shared normalization helper reduces subtle comparison bugs.

---

## `detector/src/main.py`

Phase 5 extends the main detector loop one more time by adding the bailiwick heuristic.

### New import

```python
from heuristics.bailiwick import BailiwickEnforcer
```

This imports the Phase 5 heuristic.

The main loop still follows the same architecture from earlier phases: ingestion stays separate from detection, and each heuristic is an independent module.

---

### Heuristic creation

```python
bailiwick = BailiwickEnforcer()
```

This creates one enforcer instance at startup.

The class does not currently keep long-lived state, but the interface stays consistent with the other heuristics.

That consistency helps keep `main.py` easy to extend.

---

### Run all three heuristics

```python
    alerts = matcher.process_event(event)
    alerts.extend(precursor.process_event(event))
    alerts.extend(bailiwick.process_event(event))
```

Each incoming event is now passed through three heuristics:

- Phase 3: query/response matching
- Phase 4: Kaminsky precursor detection
- Phase 5: bailiwick enforcement

Each one contributes zero or more alert dictionaries into the same list.

This is the clearest sign that the detector has become a modular pipeline rather than a one-off script.

---

### Print combined alerts

```python
    for alert in alerts:
        print(json.dumps(alert), flush=True)
```

This remains unchanged.

The important design point is that `main.py` does not need special logic for each alert type. It simply serializes whatever the heuristics produce.

That makes later phases much easier to add.

---

## `tests/test_bailiwick.py`

This file provides local validation for the bailiwick heuristic without needing Docker or a live forged response.

### Imports and path setup

```python
from datetime import datetime, timezone
import sys

sys.path.insert(0, "detector/src")
```

This matches the local-test style used in earlier phases and makes the repo modules directly importable.

---

### Test imports

```python
from heuristics.bailiwick import (
    BailiwickEnforcer,
    extract_bailiwick_zone,
    is_in_bailiwick,
)
from models import DNSEvent
```

These are the exact Phase 5 pieces under test:

- the zone-extraction helper
- the in-bailiwick check
- the main heuristic class
- the shared event model

---

### Response-event factory

```python
def make_response_event(... ) -> DNSEvent:
```

This helper builds synthetic response events for tests.

It keeps each test body short and focused by hiding repetitive `DNSEvent` construction.

```python
    return DNSEvent(
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        message_type=message_type,
        query_name=query_name,
        query_type="A",
        transaction_id=1234,
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
        authority=authority or [],
        additional=additional or [],
    )
```

The fields not relevant to Phase 5 are filled with simple defaults.

The important inputs are:

- `query_name`
- `authority`
- `additional`
- `message_type`
- `event_type`

---

### Test: zone extraction

```python
def test_extract_bailiwick_zone_examples() -> None:
```

This checks the examples from the plan:

- `www.google.com` becomes `google.com`
- `mail.sub.example.org` becomes `example.org`
- trailing-dot normalization also works

This verifies the helper behaves the way the report describes.

---

### Test: in-bailiwick helper

```python
def test_is_in_bailiwick_examples() -> None:
```

This tests the core zone-membership rule directly.

It verifies that:

- the zone itself is allowed
- subdomains of the zone are allowed
- unrelated domains are rejected

This is useful because the rest of the heuristic depends on this helper being correct.

---

### Test: normal traffic stays quiet

```python
def test_normal_in_bailiwick_records_do_not_alert() -> None:
```

This simulates a legitimate referral-style response:

- authority: `google.com NS ns1.google.com.`
- additional: `ns1.google.com A 8.8.8.8`

Both the owner names and the target names are in-bailiwick for `google.com`, so the detector should emit no alert.

That guards against obvious false positives.

---

### Test: additional-section owner name violation

```python
def test_out_of_bailiwick_additional_owner_name_alerts() -> None:
```

This simulates a response about `www.example.com` that contains an unrelated additional record:

- `bankofamerica.com A 6.6.6.6`

That is a classic out-of-bailiwick glue-style injection.

The test verifies:

- an alert is emitted
- the violating section is `additional`
- the bad field is the record `name`

---

### Test: authority-section RDATA target violation

```python
def test_out_of_bailiwick_ns_target_alerts() -> None:
```

This simulates a more subtle case:

- authority record owner name: `example.com`
- NS target in RDATA: `ns1.attacker.net.`

The owner name is fine, but the target nameserver is not.

This test proves the heuristic does more than just inspect owner names. It also checks embedded domain targets for relevant record types.

---

### Test: non-resolver responses are ignored

```python
def test_non_resolver_responses_are_ignored() -> None:
```

This ensures the heuristic ignores:

- `client_response` traffic
- query events

That keeps the detector aligned with its intended threat model and avoids analyzing the wrong layer.

---

## Detection Logic Summary

Phase 5's logic can be summarized as:

```python
for event in dnstap_stream:
    if event is not resolver_response:
        continue

    zone = extract_bailiwick_zone(event.query_name)

    for record in authority + additional:
        if record.name is outside zone:
            alert("bailiwick_violation")
        elif record target inside rdata is outside zone:
            alert("bailiwick_violation")
```

This is intentionally a simplified bailiwick heuristic, not a full recursive-resolver policy engine. The goal is to catch obviously suspicious out-of-zone records in a way that is easy to reason about and demonstrate in the project.

---

## Why Inspect Both Record Name and RDATA Target?

If the detector only checked the owner name, it would miss an important attack shape:

- `example.com NS ns1.attacker.net.`

The owner name `example.com` is technically in-bailiwick, but the response is still trying to redirect the zone toward an unrelated nameserver.

By also checking the embedded target name for selected record types, the detector catches both:

- unrelated record owners
- unrelated delegation targets

That makes the heuristic much more useful for poisoning attempts.

---

## Why Ignore the Answer Section?

Phase 5 focuses on the authority and additional sections because those are where referral-style cache poisoning tends to hide.

The answer section can still be malicious, but that is not what this heuristic is trying to decide. The answer section is better handled by other checks, such as query/response matching or later active verification.

Keeping the heuristic narrow reduces confusion and false positives.

---

## What Phase 5 Does Not Do Yet

Phase 5 is still a simplified passive detector. It does not yet:

- implement full RFC-grade bailiwick logic
- use the Public Suffix List for exact zone derivation
- confirm whether the resolver actually accepted the injected record into cache
- compare the suspicious response against trusted external resolvers
- deduplicate repeated bailiwick alerts across multiple packets

Those are later-phase concerns. Phase 5's job is to spot obviously out-of-zone authority/additional content in resolver responses.

---

## What Changed From Phase 4

Phase 4 looked for unusual query behavior over time.

Phase 5 inspects the structure of individual DNS responses.

That adds an important new perspective:

- Phase 3 asks, "Did this response match a known query?"
- Phase 4 asks, "Is the resolver suddenly querying many random names?"
- Phase 5 asks, "Does this response contain records that do not belong to the queried zone?"

With all three together, the detector now covers timing, volume, and structural response integrity.
