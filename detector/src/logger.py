import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_alert(alert: dict[str, object]) -> None:
    payload = dict(alert)
    payload["logged_at"] = _utc_now_iso()
    print(json.dumps(payload), flush=True)


def log_summary(summary: dict[str, object]) -> None:
    payload = dict(summary)
    payload["logged_at"] = _utc_now_iso()
    print(json.dumps(payload), flush=True)


@dataclass
class SummaryStats:
    interval_events_processed: int = 0
    interval_alerts_fired: int = 0
    interval_verification_results: Counter = field(default_factory=Counter)
    interval_events_by_sensor: Counter = field(default_factory=Counter)
    interval_events_by_message_type: Counter = field(default_factory=Counter)

    def record_event(self, sensor: str | None = None, message_type: str | None = None) -> None:
        self.interval_events_processed += 1
        if sensor:
            self.interval_events_by_sensor[sensor] += 1
        if message_type:
            self.interval_events_by_message_type[message_type] += 1

    def record_alert(self) -> None:
        self.interval_alerts_fired += 1

    def record_verification(self, status: str) -> None:
        self.interval_verification_results[status] += 1

    def snapshot(self, interval_seconds: int, queries_tracked: int) -> dict[str, object]:
        verification_results = {
            key: self.interval_verification_results.get(key, 0)
            for key in sorted(self.interval_verification_results)
        }
        payload = {
            "type": "summary",
            "interval_seconds": interval_seconds,
            "events_processed": self.interval_events_processed,
            "events_by_sensor": {
                key: self.interval_events_by_sensor.get(key, 0)
                for key in sorted(self.interval_events_by_sensor)
            },
            "events_by_message_type": {
                key: self.interval_events_by_message_type.get(key, 0)
                for key in sorted(self.interval_events_by_message_type)
            },
            "queries_tracked": queries_tracked,
            "alerts_fired": self.interval_alerts_fired,
            "verification_results": verification_results,
        }
        self.interval_events_processed = 0
        self.interval_alerts_fired = 0
        self.interval_verification_results.clear()
        self.interval_events_by_sensor.clear()
        self.interval_events_by_message_type.clear()
        return payload
