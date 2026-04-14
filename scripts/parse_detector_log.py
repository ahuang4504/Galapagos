#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


def parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_detector_log(path: str | Path, start_time: str | None = None) -> dict[str, object]:
    start_dt = parse_iso8601(start_time) if start_time else None
    alert_counts: Counter[str] = Counter()
    verification_counts: Counter[str] = Counter()
    total_events_processed = 0
    total_summary_alerts = 0
    first_alert_logged_at: str | None = None
    first_alert_latency_seconds: float | None = None

    for raw_line in Path(path).read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue

        if payload.get("type") == "summary":
            total_events_processed += int(payload.get("events_processed", 0))
            total_summary_alerts += int(payload.get("alerts_fired", 0))
            continue

        alert_type = payload.get("alert_type")
        if not isinstance(alert_type, str):
            continue

        alert_counts[alert_type] += 1
        verification = payload.get("verification", {})
        if isinstance(verification, dict):
            status = verification.get("status")
            if isinstance(status, str):
                verification_counts[status] += 1

        logged_at = payload.get("logged_at")
        if first_alert_logged_at is None and isinstance(logged_at, str):
            first_alert_logged_at = logged_at
            if start_dt is not None:
                first_alert_latency_seconds = max(
                    0.0,
                    (parse_iso8601(logged_at) - start_dt).total_seconds(),
                )

    return {
        "alert_counts": dict(sorted(alert_counts.items())),
        "verification_counts": dict(sorted(verification_counts.items())),
        "total_events_processed": total_events_processed,
        "total_summary_alerts": total_summary_alerts,
        "first_alert_logged_at": first_alert_logged_at,
        "first_alert_latency_seconds": first_alert_latency_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize detector JSON log lines")
    parser.add_argument("logfile")
    parser.add_argument("--start-time", default=None)
    args = parser.parse_args()
    print(json.dumps(parse_detector_log(args.logfile, start_time=args.start_time), indent=2))


if __name__ == "__main__":
    main()
