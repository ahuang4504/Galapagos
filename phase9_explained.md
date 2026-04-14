# Phase 9 Explained — Line by Line

This document walks through every file created or modified in Phase 9 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

By the end of Phase 8, the project had:

- a resolver
- a detector
- attacker tooling
- structured alert output

But it still lacked one important piece for evaluation: a realistic source of ordinary DNS traffic.

Phase 9 adds a client-side traffic generator that acts as the baseline workload for the resolver and detector.

```
Client container
├── domains.txt
└── traffic_generator.py
      ├── load baseline domain list
      ├── choose next query domain
      ├── mix repeated queries for cache hits
      ├── add jitter to timing
      └── run dig @resolver domain A +short
```

The goal is not to simulate the whole internet perfectly. The goal is to create a steady, somewhat realistic pattern of normal DNS queries so the detector can be tested for:

- zero false positives
- stable ingestion
- summary-stat visibility under normal load

This phase is especially important for the evaluation section later, because a detector is not very useful if it only works during attacks and constantly misfires during ordinary traffic.

---

## Files Added or Modified in Phase 9

Phase 9 touched these files:

- `client/traffic_generator.py`
- `client/domains.txt`
- `client/Dockerfile`
- `tests/test_traffic_generator.py`

No new third-party dependencies were added. The client container already had:

- `python3`
- `dig` from `bind-tools`

That is enough for a lightweight traffic generator.

---

## `client/traffic_generator.py`

This is the main Phase 9 file. It implements a configurable DNS traffic generator.

The generator is intentionally simple:

- it reads a domain list from a file
- it chooses domains to query
- it sometimes repeats recent domains to simulate cache hits
- it adds jitter so requests are not perfectly periodic
- it uses `dig` to send queries to the resolver

---

### Imports

```python
import argparse
import random
import subprocess
import time
from pathlib import Path
```

These imports support the generator's core tasks:

- `argparse` for CLI configuration
- `random` for domain selection and timing jitter
- `subprocess` to run `dig`
- `time` for pacing
- `Path` for file handling

Using `dig` through `subprocess` keeps the client container dependency-free beyond what it already had.

---

### Default domains file

```python
DEFAULT_DOMAINS_FILE = Path("/app/domains.txt")
```

This points the generator at the default domain list shipped in the client container.

Because the whole client directory is copied into `/app`, that path works naturally inside Docker.

The path can still be overridden at runtime with `--domains-file`.

---

### Domain loader

```python
def load_domains(domains_file: str | Path) -> list[str]:
```

This helper reads a domain list from disk and normalizes it.

```python
    path = Path(domains_file)
    domains = [
        line.strip().lower().rstrip(".")
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
```

This does three important cleanup steps:

- ignore blank lines
- ignore comment lines beginning with `#`
- normalize each domain by lowercasing and removing a trailing dot

That makes the domain list easy to maintain by hand.

```python
    if not domains:
        raise ValueError(f"no domains loaded from {path}")
```

If the file is empty after filtering, the generator fails clearly instead of running with no work to do.

This avoids confusing silent behavior.

---

### Domain-choice helper

```python
def choose_domain(domains: list[str], cache_hit_ratio: float, recent: list[str]) -> str:
```

This function decides what domain to query next.

The key idea is that normal DNS traffic is not all cache misses. Real clients often query the same names repeatedly.

```python
    if recent and random.random() < cache_hit_ratio:
        return random.choice(recent)
    return random.choice(domains)
```

This creates a simple mix:

- with probability `cache_hit_ratio`, reuse one of the recently queried domains
- otherwise choose a random domain from the broader baseline list

That produces a blend of:

- repeated queries, which are likely cache hits
- fresh queries, which are more likely cache misses

It is not a perfect traffic model, but it is enough to create a more realistic baseline than querying a totally new name every time.

---

### Sleep-interval helper

```python
def compute_sleep_interval(qps: float, jitter_ratio: float) -> float:
```

This computes how long the generator should sleep between queries.

```python
    if qps <= 0:
        raise ValueError("qps must be positive")
```

The generator requires a positive query rate. Failing fast on invalid values keeps the CLI behavior predictable.

```python
    base = 1.0 / qps
    jitter = base * jitter_ratio
    return max(0.0, random.uniform(base - jitter, base + jitter))
```

This takes the ideal interval `1 / qps` and adds random jitter around it.

For example, if:

- `qps = 5`
- base interval is `0.2` seconds
- `jitter_ratio = 0.25`

then the actual interval is sampled from a range around that base.

The `max(0.0, ...)` guard prevents a negative sleep interval if the jitter range is very large.

This matters because perfectly regular timing is unrealistic and can make both testing and visual inspection look artificial.

---

### Query runner

```python
def run_query(domain: str, resolver: str, timeout_seconds: float) -> subprocess.CompletedProcess[str]:
```

This helper sends one DNS query using `dig`.

```python
    return subprocess.run(
        [
            "dig",
            "+time=1",
            "+tries=1",
            f"+timeout={max(1, int(timeout_seconds))}",
            f"@{resolver}",
            domain,
            "A",
            "+short",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
```

Important choices here:

- `@resolver` ensures queries go to the project resolver, not system DNS
- `A` keeps the workload focused on the main record type used elsewhere in the project
- `+short` keeps command output compact
- `capture_output=True` lets the script inspect and print concise status lines
- `check=False` means failures are reported but do not crash the generator

This makes the traffic generator robust enough for long runs where some queries may fail transiently.

---

### Main generator loop

```python
def run_traffic(args: argparse.Namespace) -> None:
```

This is the script's main entry point.

```python
    domains = load_domains(args.domains_file)
    rng_recent: list[str] = []
    query_limit = args.query_count
    deadline = time.monotonic() + args.duration if args.duration else None
```

This sets up:

- the normalized domain list
- a rolling window of recently queried names
- an optional query-count limit
- an optional time-based deadline

The generator can stop either after a fixed number of queries or after a fixed duration.

```python
    print(
        "traffic generator starting:",
        f"resolver={args.resolver}",
        f"domains={len(domains)}",
        f"qps={args.qps}",
        f"cache_hit_ratio={args.cache_hit_ratio}",
        flush=True,
    )
```

This gives a clean startup summary for the operator.

That is useful when running the generator inside Docker with `docker compose exec`.

---

### Termination checks

```python
    while True:
        if query_limit is not None and sent >= query_limit:
            break
        if deadline is not None and time.monotonic() >= deadline:
            break
```

The generator supports two stop conditions:

- fixed number of queries
- fixed runtime duration

That makes it flexible for both quick tests and long baseline runs.

---

### Pick the next domain

```python
        domain = choose_domain(domains, args.cache_hit_ratio, rng_recent)
```

This is where the cache-hit simulation happens.

The more recent-domain reuse you allow, the more the resolver will likely serve from cache instead of recursing upstream every time.

That makes the client workload more representative of real browsing-like behavior.

---

### Send the query

```python
        result = run_query(domain, args.resolver, args.timeout_seconds)
        answer = result.stdout.strip().splitlines()
        status = "ok" if result.returncode == 0 else f"rc={result.returncode}"
```

This sends the DNS query and extracts a short summary of the result.

The script does not attempt deep parsing here. It just records:

- success/failure
- up to a couple of answer lines

That keeps the output easy to scan without turning the generator into a full DNS client library.

```python
        print(
            f"[{sent + 1}] domain={domain} status={status} answers={answer[:2]}",
            flush=True,
        )
```

This prints one concise log line per query.

That makes the generator useful during manual demos because you can see what it is doing in real time.

---

### Update recent-domain window

```python
        rng_recent.append(domain)
        if len(rng_recent) > args.recent_window:
            rng_recent.pop(0)
```

This maintains the rolling list of recent queries used for cache-hit reuse.

The window is capped to avoid unbounded growth.

This is a simple approximation of temporal locality in client traffic.

---

### Sleep before next query

```python
        sent += 1
        time.sleep(compute_sleep_interval(args.qps, args.jitter_ratio))
```

The generator increments its sent counter and then sleeps using the jittered interval.

This is what creates the configurable query rate.

---

### Shutdown message

```python
    print(f"traffic generator finished: queries_sent={sent}", flush=True)
```

This gives a clear termination message so the operator knows the run completed normally.

---

### CLI builder

```python
def build_parser() -> argparse.ArgumentParser:
```

This defines the runtime controls for the generator.

Important options:

- `--resolver`
- `--domains-file`
- `--qps`
- `--jitter-ratio`
- `--cache-hit-ratio`
- `--recent-window`
- `--query-count`
- `--duration`
- `--timeout-seconds`

These are enough to support:

- quick smoke tests
- moderate baseline runs
- longer low-noise evaluation runs

---

## `client/domains.txt`

This file provides the baseline query corpus for the generator.

It contains a mixed set of domains:

- popular public sites
- developer infrastructure domains
- documentation sites
- news and government sites
- academic domains

The point is not that each domain is perfectly chosen. The point is to avoid an unrealistically tiny or homogeneous traffic mix.

A broader mix helps:

- create varied cache behavior
- exercise normal resolver recursion paths
- reduce the chance that the detector is only being tested on one kind of traffic

The file is plain text so it can easily be edited for future experiments.

---

## `client/Dockerfile`

Phase 9 updates the client image so the new traffic generator and domain list are actually present in the container.

### Before

```dockerfile
COPY placeholder.py /app/placeholder.py
```

Previously only the placeholder script was copied into the client image.

That was enough for earlier scaffolding, but not enough once the client gained multiple files.

### After

```dockerfile
COPY . /app/
```

Now the whole client directory is copied into the image.

That ensures these files are available at runtime:

- `placeholder.py`
- `traffic_generator.py`
- `domains.txt`

The default container command still runs the placeholder, which is fine because the traffic generator is meant to be started manually when needed.

---

## `tests/test_traffic_generator.py`

This file provides lightweight local validation for the generator helpers.

The tests focus on the small pure functions rather than actually invoking `dig`.

That keeps the tests fast and deterministic.

---

### Imports and path setup

```python
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, "client")
```

This allows the tests to import the generator module directly from the repo layout.

---

### Helper imports

```python
from traffic_generator import choose_domain, compute_sleep_interval, load_domains
```

These are the three pure helper functions most worth testing locally.

---

### Test: domain loading and normalization

```python
def test_load_domains_ignores_comments_and_normalizes() -> None:
```

This writes a temporary domain file, loads it, and verifies:

- comment lines are ignored
- blank lines are ignored
- names are lowercased
- trailing dots are removed

That protects the user-facing domain-list format from subtle parsing bugs.

---

### Test: recent-domain reuse

```python
def test_choose_domain_can_reuse_recent_items() -> None:
```

This verifies that when `cache_hit_ratio=1.0` and there is at least one recent entry, the chooser reuses a recent domain.

That confirms the cache-hit simulation path works.

---

### Test: non-negative sleep interval

```python
def test_compute_sleep_interval_stays_non_negative() -> None:
```

This checks that even with large jitter, the computed sleep interval never goes negative.

That protects the runtime loop from invalid `time.sleep()` values.

---

### Test: positive-QPS requirement

```python
def test_compute_sleep_interval_requires_positive_qps() -> None:
```

This verifies that the helper rejects zero or negative QPS values with a clear error.

That makes invalid CLI configuration fail early and predictably.

---

## Traffic Logic Summary

Phase 9's generator can be summarized as:

```python
load domain list
recent = []

while runtime not finished:
    choose next domain
        sometimes from recent list
        sometimes from full corpus
    run dig @resolver domain A +short
    record domain in recent window
    sleep for jittered interval
```

This creates a useful normal-traffic baseline with:

- repeated names
- fresh names
- variable timing

That is enough to exercise the resolver and detector without looking like an attack.

---

## Why Simulate Cache Hits Explicitly?

If the generator only chose fresh random domains all the time, the client traffic would look abnormal:

- every query would force recursion
- there would be too few repeats
- the detector would not be tested against ordinary cache behavior

By intentionally reusing recent names some of the time, the generator creates a mix closer to real workloads, where users often revisit the same destinations repeatedly.

That matters for Phase 10 because a zero-false-positive claim means much more if the baseline traffic is at least somewhat realistic.

---

## Why Use `dig` Instead of a Python DNS Library?

The client container already had `dig` installed through `bind-tools`, so using it keeps the implementation lightweight.

Advantages:

- no new dependency
- easy to see exactly what command is being run
- simple output with `+short`

For a baseline traffic tool, that tradeoff is perfectly reasonable.

---

## What Phase 9 Does Not Do Yet

Phase 9 adds a useful baseline generator, but it still does not:

- model per-domain popularity distributions precisely
- simulate multiple independent clients
- generate AAAA, MX, TXT, or mixed record types
- adapt its traffic pattern based on previous answers
- replay real traffic traces

Those would be nice future improvements, but they are not necessary for a strong baseline experiment.

Phase 9's job is to create enough realistic normal traffic to support evaluation and false-positive testing.

---

## What Changed From Phase 8

Phase 8 made the detector's output clean and observable.

Phase 9 adds the normal-traffic side of the evaluation environment.

That means the project now has:

- a resolver
- a detector
- attacker tooling
- structured logging
- a baseline traffic generator

At this point, the setup is much closer to a full evaluation harness rather than just a detector plus attack scripts.
