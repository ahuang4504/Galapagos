# Phase 7 Explained — Line by Line

This document walks through every file created or modified in Phase 7 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

Phases 3 through 5 built passive heuristics: they can tell you when DNS traffic looks suspicious. Phase 7 adds active verification: when an alert fires, the detector checks whether the local resolver's answer agrees with trusted public resolvers.

```
Passive heuristic alert
        │
        ▼
   extract affected domain
        │
        ▼
   ActiveVerifier
   ├── query local Unbound
   ├── query Cloudflare DoH
   ├── query Google DoH
   ├── compare local vs trusted answers
   └── cache result for a short cooldown
        │
        ▼
alert JSON + verification object
```

The goal is to turn a passive signal like "this looks like a Kaminsky attempt" into something stronger:

- `MATCH` if the local resolver still agrees with trusted resolvers
- `CONFIRMED` if the local resolver diverges from trusted resolvers
- `VERIFICATION_FAILED` if the verification step itself could not complete

This phase makes the detector much more useful operationally because it can now distinguish:

- suspicious traffic that did not change resolver state
- suspicious traffic that appears to have changed the resolver's answers

---

## Files Added or Modified in Phase 7

Phase 7 touched these files:

- `detector/src/verification.py`
- `detector/src/main.py`
- `detector/requirements.txt`
- `requirements.txt`
- `tests/test_verification.py`

The main change is a new verification module plus alert enrichment in the detector loop.

---

## `detector/requirements.txt` and top-level `requirements.txt`

### Added dependency

```python
httpx>=0.25.0
```

Phase 7 needs `httpx` because the detector must make outbound HTTPS requests to DNS-over-HTTPS endpoints.

`httpx` is used for:

- Cloudflare DoH queries
- Google DoH queries
- async concurrent verification requests

It belongs in:

- `detector/requirements.txt` for the detector container
- top-level `requirements.txt` for local development and testing

Earlier phases no longer used `httpx`, but Phase 7 brings it back because active verification depends on it.

---

## `detector/src/verification.py`

This is the main Phase 7 file. It contains:

- DoH query logic
- local-resolver query logic
- comparison logic
- verification-result caching

---

### Imports

```python
import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.rcode
import dns.resolver
import httpx
```

These imports support four jobs:

- concurrency with `asyncio`
- environment-variable configuration
- typed result objects with `dataclass`
- DNS lookups through both `dnspython` and `httpx`

`dns.resolver` is used for the local Unbound query, while `httpx` is used for remote DoH requests.

---

### Resolver endpoint constants

```python
CLOUDFLARE_DOH_URL = os.getenv(
    "CLOUDFLARE_DOH_URL",
    "https://cloudflare-dns.com/dns-query",
)
GOOGLE_DOH_URL = os.getenv(
    "GOOGLE_DOH_URL",
    "https://dns.google/resolve",
)
LOCAL_RESOLVER_IP = os.getenv("LOCAL_RESOLVER_IP", "172.28.0.10")
```

These constants make the verifier configurable without changing code.

Defaults are provided for the normal Docker lab:

- local resolver at `172.28.0.10`
- Cloudflare DoH
- Google DoH

Using environment variables makes it easy to test alternate resolvers or simulate failure scenarios later.

---

### Lookup result dataclass

```python
@dataclass
class ResolverLookup:
    answers: list[str]
    rcode: str
```

This stores the result of one DNS lookup from one resolver.

It includes:

- `answers`: the returned `A` records
- `rcode`: the DNS response code, such as `NOERROR` or `NXDOMAIN`

Why include `rcode` instead of only answers?

Because an empty answer list can mean different things:

- the name does not exist
- the query succeeded but returned no `A` answers
- an error happened

The response code keeps those cases distinct.

---

### Verification result dataclass

```python
@dataclass
class VerificationResult:
    status: str
    domain: str
    local_answer: list[str]
    trusted_answers: dict[str, list[str]]
    local_rcode: str
    trusted_rcodes: dict[str, str]
    verified_at: str
    reason: str | None = None
```

This is the structured output of the whole verification step.

Fields:

- `status`: `MATCH`, `CONFIRMED`, or `VERIFICATION_FAILED`
- `domain`: the domain that was verified
- `local_answer`: what the local resolver returned
- `trusted_answers`: what Cloudflare and Google returned
- `local_rcode`: local DNS status code
- `trusted_rcodes`: remote DNS status codes
- `verified_at`: timestamp of the verification
- `reason`: optional error explanation when verification fails

This dataclass gives the detector a consistent object to attach to alerts.

---

### Serialization helper

```python
def to_dict(self) -> dict[str, object]:
```

This converts a `VerificationResult` into a JSON-ready dictionary.

```python
    payload: dict[str, object] = {
        "status": self.status,
        "domain": self.domain,
        "local_answer": self.local_answer,
        "trusted_answers": self.trusted_answers,
        "local_rcode": self.local_rcode,
        "trusted_rcodes": self.trusted_rcodes,
        "verified_at": self.verified_at,
    }
    if self.reason:
        payload["reason"] = self.reason
```

The optional `reason` field is only included when verification actually failed.

That keeps the successful output compact while still exposing useful debugging context during failures.

---

### DoH query function

```python
async def query_doh(
    domain: str,
    resolver_url: str,
    client: httpx.AsyncClient | None = None,
) -> ResolverLookup:
```

This sends one DNS-over-HTTPS query and returns a `ResolverLookup`.

```python
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=5.0, follow_redirects=True)
```

The function supports dependency injection for tests:

- if a client is passed in, use it
- otherwise create a real `httpx.AsyncClient`

That makes the function easy to test without live network access.

```python
    headers = {}
    if "cloudflare-dns.com" in resolver_url:
        headers["Accept"] = "application/dns-json"
```

Cloudflare's JSON DoH endpoint expects the `Accept: application/dns-json` header.

Google's JSON endpoint does not require it, so the header is added only for Cloudflare-style URLs.

```python
    response = await client.get(
        resolver_url,
        params={"name": domain, "type": "A"},
        headers=headers,
    )
    response.raise_for_status()
    payload = response.json()
```

This performs the actual HTTPS GET request and parses the returned JSON.

The query is fixed to type `A` because the current project only verifies IPv4 answers.

```python
    rcode_value = int(payload.get("Status", 0))
```

The DoH JSON response uses integer DNS status codes.

Those are converted into standard DNS text codes next.

```python
    answers = [
        answer["data"]
        for answer in payload.get("Answer", [])
        if answer.get("type") == 1 and "data" in answer
    ]
```

This keeps only IPv4 `A` answers from the response.

That avoids mixing in unrelated record types like CNAMEs when the verifier wants to compare the final IPv4 answer set.

```python
    return ResolverLookup(
        answers=answers,
        rcode=dns.rcode.to_text(rcode_value),
    )
```

The lookup result is normalized into the same shape used elsewhere in the verifier.

```python
    finally:
        if owns_client:
            await client.aclose()
```

If the function created the client itself, it also closes it.

This avoids leaving open HTTP connections behind.

---

### Local resolver query function

```python
def query_local_resolver(domain: str, resolver_ip: str) -> ResolverLookup:
```

This queries the local Unbound instance directly.

```python
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
```

The resolver is configured explicitly so it does not use the host machine's system DNS settings.

That is important because the detector must query the project resolver, not whatever DNS the host happens to use.

```python
    try:
        answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
```

This sends the local query for an `A` record.

```python
    except dns.resolver.NXDOMAIN:
        return ResolverLookup(answers=[], rcode="NXDOMAIN")
```

If the local resolver says the name does not exist, that is treated as a valid outcome rather than a crash.

```python
    except dns.resolver.NoAnswer:
        return ResolverLookup(answers=[], rcode="NOERROR")
```

This means the lookup succeeded at the DNS protocol level but produced no `A` answers.

```python
    except dns.exception.DNSException as exc:
        raise RuntimeError(f"local resolver query failed: {exc}") from exc
```

Other DNS exceptions are treated as verification failures.

That is the right behavior because the detector cannot confidently compare answers if the local check itself breaks.

```python
    return ResolverLookup(
        answers=[item.address for item in answer],
        rcode=dns.rcode.to_text(answer.response.rcode()),
    )
```

On success, the function returns the local IPv4 answers plus the response code.

---

### Main verification function

```python
async def verify_domain(
    domain: str,
    local_resolver_ip: str = LOCAL_RESOLVER_IP,
    *,
    cloudflare_url: str = CLOUDFLARE_DOH_URL,
    google_url: str = GOOGLE_DOH_URL,
) -> VerificationResult:
```

This is the core Phase 7 function.

It:

1. queries the local resolver
2. queries Cloudflare and Google concurrently
3. compares the local answer against the trusted union
4. returns a structured verification result

---

### Normalize domain and timestamp

```python
    normalized = domain.rstrip(".").lower()
    verified_at = datetime.now(timezone.utc).isoformat()
```

This ensures consistent domain handling and captures when the verification happened.

The verification timestamp is separate from the original alert timestamp because verification may happen a short time later.

---

### Local verification failure handling

```python
    try:
        local_lookup = query_local_resolver(normalized, local_resolver_ip)
    except Exception as exc:
        return VerificationResult(
            status="VERIFICATION_FAILED",
            ...
            reason=str(exc),
        )
```

If the local resolver query itself fails, the verifier returns a structured failure result rather than crashing the detector.

That keeps the alert pipeline resilient.

---

### Remote DoH queries in parallel

```python
    try:
        cloudflare_lookup, google_lookup = await asyncio.gather(
            query_doh(normalized, cloudflare_url),
            query_doh(normalized, google_url),
        )
```

This is the concurrency payoff the earlier async architecture was preparing for.

Cloudflare and Google are queried at the same time instead of one after the other.

That reduces latency and keeps verification practical in the main event loop.

```python
    except Exception as exc:
        return VerificationResult(
            status="VERIFICATION_FAILED",
            ...
            reason=str(exc),
        )
```

If either DoH query fails, the verifier returns a structured failure result.

This is important because verification should enrich alerts, not bring the whole detector down.

---

### Trusted-answer maps

```python
    trusted_answers = {
        "cloudflare": cloudflare_lookup.answers,
        "google": google_lookup.answers,
    }
    trusted_rcodes = {
        "cloudflare": cloudflare_lookup.rcode,
        "google": google_lookup.rcode,
    }
```

These dictionaries preserve per-resolver results instead of collapsing them immediately.

That is useful for:

- human debugging
- explaining disagreement between trusted resolvers
- attaching richer verification context to alerts

---

### NXDOMAIN comparison

```python
    if local_lookup.rcode == "NXDOMAIN":
        status = (
            "MATCH"
            if cloudflare_lookup.rcode == "NXDOMAIN" and google_lookup.rcode == "NXDOMAIN"
            else "CONFIRMED"
        )
```

This handles the case where the local resolver says the name does not exist.

If both trusted resolvers also say `NXDOMAIN`, that is a match.

If the local resolver says `NXDOMAIN` but trusted resolvers return something else, the divergence is treated as confirmed suspicious behavior.

---

### Normal answer comparison

```python
    else:
        trusted_union = set(cloudflare_lookup.answers) | set(google_lookup.answers)
        local_answers = set(local_lookup.answers)
        status = "MATCH" if local_answers.issubset(trusted_union) else "CONFIRMED"
```

This is the main comparison logic.

The union of Cloudflare and Google answers is treated as the trusted baseline.

Why use a union?

Because CDNs and geo-load-balancing can legitimately cause different trusted resolvers to return different but still valid IPs.

The rule is:

- if every local answer is present in the trusted union, call it `MATCH`
- otherwise call it `CONFIRMED`

`CONFIRMED` here means the passive alert now has supporting evidence that the local resolver diverged from the trusted baseline.

---

### Final result object

```python
    return VerificationResult(
        status=status,
        domain=normalized,
        local_answer=local_lookup.answers,
        trusted_answers=trusted_answers,
        local_rcode=local_lookup.rcode,
        trusted_rcodes=trusted_rcodes,
        verified_at=verified_at,
    )
```

This bundles all verification information into one object that can be attached directly to an alert.

---

### Cached verifier class

```python
class ActiveVerifier:
```

This class adds short-term verification-result caching.

That solves a practical problem: if a Kaminsky flood triggers many alerts for the same domain, the detector should not hammer Cloudflare and Google with identical verification requests every time.

---

### Constructor

```python
def __init__(
    self,
    local_resolver_ip: str = LOCAL_RESOLVER_IP,
    cooldown_seconds: int = 30,
    verifier=verify_domain,
) -> None:
```

The active verifier stores:

- the local resolver IP
- a cooldown window for cached results
- the verification function to call

The `verifier=verify_domain` parameter also makes the class easy to unit test by injecting a fake verifier.

```python
    self.cache: dict[str, tuple[datetime, VerificationResult]] = {}
```

The cache maps a normalized domain to:

- when the verification ran
- what the result was

---

### Cached verify method

```python
async def verify(self, domain: str) -> VerificationResult:
```

This is the public API used by `main.py`.

```python
    normalized = domain.rstrip(".").lower()
    now = datetime.now(timezone.utc)
    cached = self.cache.get(normalized)
    if cached and now - cached[0] <= self.cooldown:
        return cached[1]
```

If the same domain was verified recently, reuse the cached result.

That is the deduplication step called for in the Phase 7 plan.

```python
    result = await self.verifier(normalized, self.local_resolver_ip)
    self.cache[normalized] = (now, result)
    return result
```

If there is no usable cache entry, run fresh verification, store it, and return it.

---

## `detector/src/main.py`

Phase 7 enriches every alert with active verification data.

---

### New imports

```python
import os
...
from verification import ActiveVerifier
```

`os` is used for an environment-variable toggle, and `ActiveVerifier` is the new Phase 7 verification component.

---

### Verification toggle

```python
ENABLE_VERIFICATION = os.getenv("ENABLE_VERIFICATION", "1") != "0"
```

This allows verification to be disabled without editing code.

That is useful if:

- the environment has no outbound network access
- you want to benchmark passive detection only
- you are debugging the detector without DoH traffic

---

### Alert-domain extraction helper

```python
def extract_alert_domain(alert: dict[str, object]) -> str | None:
```

Different heuristics name their affected domain differently:

- Phase 3 uses `domain`
- Phase 4 uses `target_domain`
- Phase 5 may want either the injected record name or the original query domain

This helper normalizes that into one value for verification.

```python
    if alert_type == "kaminsky_precursor":
        domain = alert.get("target_domain")
```

Phase 4 alerts are grouped by parent domain, so that is the obvious verification target.

```python
    elif alert_type == "bailiwick_violation":
        record = alert.get("violating_record", {})
        if isinstance(record, dict) and record.get("type") in {"A", "AAAA"}:
            domain = record.get("name")
        else:
            domain = alert.get("query_domain")
```

For bailiwick alerts, verification chooses:

- the injected record name for `A`/`AAAA` violations
- otherwise the original query domain

This is a practical choice so a forged additional `A` record for `bankofamerica.com` gets verified as `bankofamerica.com`, which is usually what the operator cares about.

```python
    else:
        domain = alert.get("domain")
```

Phase 3 uses `domain`, so that is the default fallback.

---

### Verifier creation

```python
verifier = ActiveVerifier() if ENABLE_VERIFICATION else None
```

The detector creates one verifier instance at startup and reuses it for all alerts.

That lets the cache work across the entire run.

---

### Attach verification to each alert

```python
        for alert in alerts:
            if verifier is not None:
                domain = extract_alert_domain(alert)
                if domain:
                    result = await verifier.verify(domain)
                    alert["verification"] = result.to_dict()
            print(json.dumps(alert), flush=True)
```

This is the main Phase 7 integration point.

For each alert:

1. extract the domain to verify
2. run cached active verification
3. attach the verification object to the alert
4. print the enriched alert as JSON

That turns every passive alert into a more informative hybrid alert.

---

## `tests/test_verification.py`

This file provides local validation for Phase 7 without requiring live network access.

Because the current host environment may not have `httpx` installed, the test file includes a small compatibility shim before importing the verification module.

---

### Optional `httpx` shim

```python
try:
    import httpx
except ModuleNotFoundError:
    fake_httpx = types.SimpleNamespace(...)
    sys.modules["httpx"] = fake_httpx
```

This allows the verification module to import in lightweight local environments even when the real `httpx` package is not installed.

The actual detector container still installs the real dependency.

---

### Fake response and fake client

```python
class FakeResponse:
...

class FakeAsyncClient:
...
```

These helper classes simulate a DoH HTTP response and an async HTTP client.

That allows `query_doh()` to be tested without making real network requests.

---

### Test: DoH parsing

```python
def test_query_doh_parses_a_answers() -> None:
```

This verifies that `query_doh()`:

- reads the JSON payload
- ignores non-`A` record types
- returns a `ResolverLookup` with `NOERROR`

This is the smallest unit test for the DoH parser itself.

---

### Test: trusted union matching

```python
def test_verify_domain_match_uses_union_of_trusted_answers() -> None:
```

This verifies the main happy-path comparison logic.

The local resolver returns one IP, Cloudflare returns that IP, and Google returns a different but still legitimate IP.

The result should still be `MATCH` because the local answer is a subset of the trusted union.

That test is important because it protects against false positives caused by CDN variability.

---

### Test: divergence

```python
def test_verify_domain_divergence_returns_confirmed() -> None:
```

This verifies that when the local resolver returns an answer outside the trusted baseline, verification returns `CONFIRMED`.

This is the key Phase 7 success condition for a poisoned-cache scenario.

---

### Test: NXDOMAIN agreement

```python
def test_verify_domain_handles_nxdomain_match() -> None:
```

This checks the edge case where the local resolver says a domain does not exist and trusted resolvers agree.

That should be treated as `MATCH`, not as a failure.

---

### Test: DoH failure

```python
def test_verify_domain_handles_doh_failure() -> None:
```

This verifies that network or DoH errors become `VERIFICATION_FAILED` rather than crashing the detector.

Graceful failure is essential here because verification should enrich alerts, not destabilize the detector.

---

### Test: cache reuse

```python
def test_active_verifier_uses_cache() -> None:
```

This injects a fake verifier and checks that verifying the same domain twice inside the cooldown window only performs one actual verification.

That proves the deduplication cache is working.

---

### Test: alert-domain extraction

```python
def test_extract_alert_domain_prefers_bailiwick_a_record_name() -> None:
```

This checks one heuristic-specific extraction rule:

for an `A`-record bailiwick violation, the domain chosen for verification should be the injected record name rather than the original query name.

That gives Phase 5 alerts more meaningful active verification behavior.

---

## Verification Logic Summary

Phase 7's logic can be summarized as:

```python
for each passive alert:
    domain = extract_domain(alert)
    if cached verification exists:
        use it
    else:
        local = query local resolver
        trusted = query Cloudflare and Google concurrently
        if local differs from trusted:
            status = "CONFIRMED"
        elif queries succeed and agree:
            status = "MATCH"
        else:
            status = "VERIFICATION_FAILED"
```

This is the bridge from passive anomaly detection to stronger evidence about resolver state.

---

## Why Use Two Trusted Resolvers?

A single public resolver can disagree for benign reasons:

- CDN locality
- transient routing differences
- resolver-specific behavior

Using both Cloudflare and Google and taking the union of answers makes the detector more tolerant of those normal differences.

That reduces false positives while still providing a strong baseline.

---

## Why Cache Verification Results?

During an active attack, the detector can emit many passive alerts for the same domain in a short period.

Without caching, each alert would trigger:

- one local query
- one Cloudflare DoH query
- one Google DoH query

That would be wasteful, slow, and noisy.

The short cooldown cache gives a practical balance:

- recent verification is reused
- stale results naturally age out
- the detector avoids rechecking the same domain over and over every second

---

## What Phase 7 Does Not Do Yet

Phase 7 adds active verification, but it still does not:

- deduplicate alerts themselves
- verify record types other than `A`
- perform deep semantic comparison of delegation records
- maintain long-term verification history on disk
- classify attacks into more detailed categories beyond `MATCH`, `CONFIRMED`, and `VERIFICATION_FAILED`

Those are later refinements.

Phase 7's job is to add a simple, practical active check that strengthens passive alerts with outside confirmation.

---

## What Changed From Phase 6

Phase 6 added attacker tooling that could generate suspicious DNS traffic.

Phase 7 adds a second layer of confidence on the detector side:

- passive heuristics say the traffic looks suspicious
- active verification says whether the resolver's answer actually diverges from trusted resolvers

That is the point where the project becomes much closer to a real incident-detection workflow rather than only a traffic-pattern monitor.
