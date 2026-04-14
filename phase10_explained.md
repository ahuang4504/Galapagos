# Phase 10 Explained — Line by Line

This document walks through every file created or modified in Phase 10 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

By the end of Phase 9, the project had all the moving pieces needed for experiments:

- resolver
- detector
- attacker tooling
- traffic generator
- structured logs

Phase 10 adds the evaluation harness that ties those pieces together into repeatable scenarios and machine-readable results.

There are two main pieces in this phase:

1. `scripts/run_evaluation.sh` — orchestrates the scenarios
2. `scripts/parse_detector_log.py` — summarizes detector JSON output into a compact result structure

```
run_evaluation.sh
├── bring stack up/down per config
├── launch detector log capture
├── run baseline traffic or attack scripts
├── collect post-attack dig results
├── parse detector log into scenario summary
└── append one row to results_table.md

parse_detector_log.py
├── read detector JSON lines
├── count alert types
├── count verification statuses
├── sum summary event totals
└── compute first-alert latency
```

The goal is to automate the results table the project has been building toward:

- normal traffic baseline
- Kaminsky flood against weak and hardened configs
- bailiwick injection against weak and hardened configs

That turns the project from "a collection of scripts" into a repeatable evaluation workflow.

---

## Files Added or Modified in Phase 10

Phase 10 touched these files:

- `scripts/run_evaluation.sh`
- `scripts/parse_detector_log.py`
- `tests/test_parse_detector_log.py`
- `phase10_explained.md`

No new third-party dependencies were added. The harness relies on tools the project already expects:

- `docker`
- `python3`
- the existing container scripts and detector JSON output

---

## `scripts/parse_detector_log.py`

This helper reads detector logs and produces a compact JSON summary for one scenario.

That keeps the shell orchestration script much simpler than trying to parse JSON in pure bash.

---

### Imports

```python
import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
```

These imports support:

- CLI argument parsing
- JSON decoding
- categorical counting
- ISO timestamp parsing
- filesystem access

The helper is intentionally lightweight and standalone.

---

### ISO timestamp parser

```python
def parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
```

This converts detector timestamps into Python `datetime` objects.

It also normalizes a trailing `Z` into `+00:00` so both common UTC forms are accepted.

That makes the latency calculation robust.

---

### Main parser function

```python
def parse_detector_log(path: str | Path, start_time: str | None = None) -> dict[str, object]:
```

This is the core Phase 10 parser.

Inputs:

- a detector log file
- an optional scenario start time

Output:

- a compact summary dictionary describing what the detector saw

---

### Start-time handling

```python
    start_dt = parse_iso8601(start_time) if start_time else None
```

If a scenario start time is provided, the parser will compute first-alert latency relative to it.

If not, latency is left as `None`.

That lets the helper work for both quick ad hoc summaries and full scenario evaluation.

---

### Counters and accumulators

```python
    alert_counts: Counter[str] = Counter()
    verification_counts: Counter[str] = Counter()
    total_events_processed = 0
    total_summary_alerts = 0
    first_alert_logged_at: str | None = None
    first_alert_latency_seconds: float | None = None
```

These track the core results the evaluation harness cares about:

- which passive alert types fired
- which verification statuses appeared
- how many events the detector processed in summaries
- when the first alert was logged
- how long it took to appear

This is enough to populate the results table and compare scenario behavior.

---

### Line-by-line parsing

```python
    for raw_line in Path(path).read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
```

The helper reads the detector log as line-delimited JSON.

Blank lines are ignored.

That matches the output style established in Phase 8.

---

### Ignore non-JSON lines safely

```python
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
```

If the log contains any stray non-JSON lines, they are skipped rather than crashing the parser.

That makes the helper more tolerant of operational noise.

---

### Summary-object handling

```python
        if payload.get("type") == "summary":
            total_events_processed += int(payload.get("events_processed", 0))
            total_summary_alerts += int(payload.get("alerts_fired", 0))
            continue
```

Phase 8 introduced periodic summary objects.

This code:

- detects them by `type == "summary"`
- accumulates their event and alert counts
- skips the rest of the alert-specific logic

That means the parser can consume the mixed alert/summary stream without confusion.

---

### Alert-type handling

```python
        alert_type = payload.get("alert_type")
        if not isinstance(alert_type, str):
            continue

        alert_counts[alert_type] += 1
```

Any JSON object that is not a summary and has a string `alert_type` is treated as an alert.

The alert type is counted so the evaluation harness can summarize which passive heuristics fired in a scenario.

---

### Verification-status counting

```python
        verification = payload.get("verification", {})
        if isinstance(verification, dict):
            status = verification.get("status")
            if isinstance(status, str):
                verification_counts[status] += 1
```

If the alert includes a Phase 7 verification object, the parser counts its status.

This lets the evaluation harness answer questions like:

- did verification produce `MATCH`?
- did it produce `CONFIRMED`?
- did it fail?

---

### First-alert latency

```python
        logged_at = payload.get("logged_at")
        if first_alert_logged_at is None and isinstance(logged_at, str):
            first_alert_logged_at = logged_at
            if start_dt is not None:
                first_alert_latency_seconds = max(
                    0.0,
                    (parse_iso8601(logged_at) - start_dt).total_seconds(),
                )
```

The first alert seen in the log becomes the scenario's detection point.

If a scenario start time was supplied, the parser computes latency in seconds.

Using `max(0.0, ...)` avoids negative values if timestamps are slightly out of sync.

---

### Final summary object

```python
    return {
        "alert_counts": dict(sorted(alert_counts.items())),
        "verification_counts": dict(sorted(verification_counts.items())),
        "total_events_processed": total_events_processed,
        "total_summary_alerts": total_summary_alerts,
        "first_alert_logged_at": first_alert_logged_at,
        "first_alert_latency_seconds": first_alert_latency_seconds,
    }
```

This returns a compact summary payload suitable for:

- writing to a scenario summary file
- feeding into the results table
- ad hoc debugging

The alert and verification maps are sorted for stable output.

---

### CLI entry point

```python
def main() -> None:
```

This turns the parser into a reusable command-line tool.

```python
    parser = argparse.ArgumentParser(description="Summarize detector JSON log lines")
    parser.add_argument("logfile")
    parser.add_argument("--start-time", default=None)
```

The parser accepts:

- the detector log path
- an optional scenario start time

```python
    print(json.dumps(parse_detector_log(args.logfile, start_time=args.start_time), indent=2))
```

This prints the summarized scenario result as JSON, which the shell script can then store or reuse.

---

## `scripts/run_evaluation.sh`

This is the main Phase 10 orchestration script.

It automates the evaluation scenarios and builds a markdown results table.

---

### Shell mode and working directory

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
```

This makes the script:

- run under bash
- fail on undefined variables or command errors
- operate from the repo root regardless of where it was launched from

That is standard and important for a project orchestration script.

---

### Results directory and table setup

```bash
RESULTS_ROOT="${RESULTS_ROOT:-results}"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="$RESULTS_ROOT/evaluation_$TIMESTAMP"
TABLE_FILE="$RUN_DIR/results_table.md"
```

Each evaluation run gets its own timestamped directory.

That keeps runs separate and prevents later runs from overwriting earlier results.

```bash
mkdir -p "$RUN_DIR"

cat > "$TABLE_FILE" <<'EOF'
| Scenario | Config | Passive Alerts | Verification | Cache Poisoned | Detection Latency |
|---|---|---|---|---|---|
EOF
```

This creates the results directory and initializes the markdown results table with the planned columns.

That means the evaluation output is immediately human-readable.

---

### Scenario tuning variables

```bash
BASELINE_DURATION_SECONDS="${BASELINE_DURATION_SECONDS:-300}"
ATTACK_BACKGROUND_DURATION_SECONDS="${ATTACK_BACKGROUND_DURATION_SECONDS:-120}"
BASELINE_QPS="${BASELINE_QPS:-5}"
...
```

These environment-driven variables make the harness configurable without editing the script.

They control:

- how long baseline runs last
- how much background traffic runs during attack scenarios
- Kaminsky attack parameters
- bailiwick-injection parameters

This is useful because evaluation often needs repeated tuning.

---

### Command checks

```bash
require_command docker
require_command python3
```

The harness fails early if required tools are missing.

That gives the operator an immediate useful error instead of a confusing later failure.

---

### Stack lifecycle helpers

```bash
compose_up() {
    local config="$1"
    UNBOUND_CONFIG="$config" docker compose up -d --build
}
```

This brings the project up with either the weak or hardened Unbound config.

The config is selected through the existing `UNBOUND_CONFIG` environment variable.

```bash
compose_down() {
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
```

This tears the stack down between scenarios.

Removing volumes helps reduce state carryover between runs, which is important for repeatable experiments.

---

### Detector-log capture

```bash
start_detector_capture() {
    docker compose logs -f --no-log-prefix detector > "$logfile" 2>&1 &
    DETECTOR_LOG_PID=$!
}
```

This tails the detector output in the background and writes it to a scenario-specific log file.

`--no-log-prefix` is important because the parser expects raw JSON lines, not service-name prefixes.

```bash
stop_detector_capture() {
    kill "$DETECTOR_LOG_PID" ...
}
```

This cleanly stops the background log capture once the scenario is finished.

---

### UTC timestamp helper

```bash
utc_now() {
    python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat())
PY
}
```

This provides a portable way to generate ISO UTC timestamps from bash.

Using Python here avoids shell portability issues around timezone formatting.

That timestamp becomes the scenario start time used for latency calculations.

---

### Baseline traffic helpers

```bash
run_baseline_traffic() { ... }
run_background_traffic() { ... }
wait_for_background_traffic() { ... }
```

These wrap Phase 9's traffic generator for two use cases:

- run normal traffic as the main scenario
- run normal traffic in the background while an attack is underway

That matches the Phase 10 plan closely.

---

### Log parsing helper

```bash
parse_log_to_file() {
    python3 scripts/parse_detector_log.py "$logfile" --start-time "$start_time" > "$summary_file"
}
```

This runs the parser helper and saves the scenario summary JSON.

That gives each scenario both:

- raw detector logs
- a compact derived summary

---

### Summary-field helpers

```bash
extract_summary_field() { ... }
format_passive_alerts() { ... }
format_verification_status() { ... }
```

These small helpers make it easy to turn the parser's JSON output into the values needed for the markdown table.

Examples:

- render passive alert types as `precursor + duplicate_response`
- choose a dominant verification status
- extract detection latency

This avoids trying to hand-parse JSON in bash.

---

### Results-table append helper

```bash
append_result_row() {
    printf '| %s | %s | %s | %s | %s | %s |\n' ...
}
```

This appends one markdown row per scenario.

That makes the final output immediately suitable for inclusion in the project writeup.

---

### Scenario 1: normal traffic

```bash
scenario_normal_traffic() { ... }
```

This runs the baseline scenario for either config.

Flow:

1. tear down any previous stack
2. bring up the requested config
3. start detector log capture
4. record scenario start time
5. run baseline traffic for the configured duration
6. stop detector capture
7. parse the logs
8. append a row to the results table

The `Cache Poisoned` and `Detection Latency` columns are filled with `No` and `N/A` for this baseline scenario.

---

### Scenario 2/3: Kaminsky flood

```bash
scenario_kaminsky() { ... }
```

This automates the Kaminsky attack scenario for weak and hardened configs.

Flow:

1. reset and bring up the stack
2. start detector log capture
3. start background normal traffic
4. launch the attacker flood
5. let the detector settle briefly
6. `dig` the target domain from the client to check whether poisoning appears to have succeeded
7. stop detector capture
8. parse logs and append a results row

The script records:

- passive alert types observed
- dominant verification result
- whether the post-attack `dig` returned the spoofed IP
- first-alert latency

That is the automation equivalent of the manual Phase 10 evaluation plan.

---

### Scenario 4/5: bailiwick injection

```bash
scenario_bailiwick() { ... }
```

This does the same kind of orchestration for the simpler bailiwick-injection attack.

Instead of running the Kaminsky flood tool, it runs `bailiwick_inject.py` and then queries the injected name to see whether the resolver appears to have cached the injected record.

This scenario is especially important for exercising the Phase 5 heuristic.

---

### Main function

```bash
main() {
    scenario_normal_traffic weak "Normal traffic"
    scenario_normal_traffic hardened "Normal traffic"
    scenario_kaminsky weak "Kaminsky flood"
    scenario_kaminsky hardened "Kaminsky flood"
    scenario_bailiwick weak "Bailiwick injection"
    scenario_bailiwick hardened "Bailiwick injection"
    compose_down
    ...
}
```

This runs the full evaluation matrix in the same order as the project plan.

At the end, it prints the final results table to stdout and leaves the run artifacts in the timestamped results directory.

That makes the script useful both for interactive runs and for report generation.

---

## `tests/test_parse_detector_log.py`

This file provides lightweight validation for the parser helper.

The orchestration script itself is mostly shell glue, but the parser performs the most important result-reduction logic, so it is worth testing directly.

---

### Imports and path setup

```python
import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, "scripts")
```

This lets the test import the parser helper directly from the repo.

---

### Parser import

```python
from parse_detector_log import parse_detector_log
```

The test focuses on the reusable core function rather than only the CLI wrapper.

---

### Test: mixed alert and summary parsing

```python
def test_parse_detector_log_summarizes_alerts_and_summaries() -> None:
```

This creates a temporary detector log file containing:

- one summary object
- one `kaminsky_precursor` alert
- one `duplicate_response` alert

Then it verifies that the parser:

- counts both alert types
- counts both verification statuses
- sums the summary's event count
- captures the first alert timestamp
- computes first-alert latency correctly

That gives confidence that the evaluation harness can actually reduce detector output into useful metrics.

---

## Evaluation Logic Summary

Phase 10's harness can be summarized as:

```bash
for each scenario:
    reset stack
    bring up weak or hardened config
    capture detector logs
    run baseline traffic and/or attack
    query resolver after attack
    parse detector logs into summary JSON
    append one markdown row to results table
```

The parser helper then reduces detector output into:

- passive alert counts
- verification-result counts
- event totals
- first-alert latency

That is exactly the kind of information needed for the evaluation chapter later.

---

## Why Split Parsing Out of the Shell Script?

Shell is fine for orchestration:

- start containers
- run commands
- collect files

But it is awkward for structured JSON parsing and timestamp arithmetic.

By splitting the log summarization into a small Python helper, the overall design gets:

- cleaner bash
- easier testing
- less fragile parsing logic

This is a good tradeoff for an evaluation harness.

---

## Why Use Detector Logs Instead of Internal State Dumps?

The harness measures what the detector actually emits, not hidden internal counters.

That is important because:

- it reflects the operator-visible behavior
- it validates the JSON output format from Phase 8
- it ties the evaluation directly to the same artifacts the writeup will quote

In other words, the harness evaluates the detector as it is actually used.

---

## What Phase 10 Does Not Do Yet

Phase 10 provides a useful automation layer, but it still does not:

- retry flaky attack runs automatically
- compute aggregated multi-run statistics
- graph results
- export CSV alongside markdown
- validate scenario expectations automatically against pass/fail thresholds

Those are reasonable future improvements.

Phase 10's main job is to make the evaluation repeatable and to generate a coherent results table automatically.

---

## What Changed From Phase 9

Phase 9 added normal client traffic for baseline experiments.

Phase 10 turns the project into an actual experiment runner:

- scenarios are automated
- detector logs are summarized automatically
- results are compiled into a markdown table

At this point, the project is much closer to a full research/demo pipeline rather than a set of individual components.
