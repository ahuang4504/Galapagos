import io
import json
import sys

sys.path.insert(0, "detector/src")

from logger import SummaryStats, log_alert, log_summary


def test_log_alert_emits_json_with_logged_at() -> None:
    buffer = io.StringIO()
    original_stdout = sys.stdout
    try:
        sys.stdout = buffer
        log_alert({"alert_type": "duplicate_response", "domain": "example.com"})
    finally:
        sys.stdout = original_stdout

    payload = json.loads(buffer.getvalue())
    assert payload["alert_type"] == "duplicate_response"
    assert payload["domain"] == "example.com"
    assert "logged_at" in payload


def test_log_summary_emits_json_with_type_and_logged_at() -> None:
    buffer = io.StringIO()
    original_stdout = sys.stdout
    try:
        sys.stdout = buffer
        log_summary(
            {
                "type": "summary",
                "interval_seconds": 60,
                "events_processed": 10,
                "queries_tracked": 2,
                "alerts_fired": 1,
                "verification_results": {"MATCH": 1},
            }
        )
    finally:
        sys.stdout = original_stdout

    payload = json.loads(buffer.getvalue())
    assert payload["type"] == "summary"
    assert payload["interval_seconds"] == 60
    assert payload["events_processed"] == 10
    assert "logged_at" in payload


def test_summary_stats_snapshot_resets_interval_counts() -> None:
    stats = SummaryStats()
    stats.record_event()
    stats.record_event()
    stats.record_alert()
    stats.record_verification("MATCH")
    stats.record_verification("MATCH")
    stats.record_verification("CONFIRMED")

    snapshot = stats.snapshot(interval_seconds=60, queries_tracked=3)
    assert snapshot["type"] == "summary"
    assert snapshot["events_processed"] == 2
    assert snapshot["queries_tracked"] == 3
    assert snapshot["alerts_fired"] == 1
    assert snapshot["verification_results"] == {"CONFIRMED": 1, "MATCH": 2}

    second = stats.snapshot(interval_seconds=60, queries_tracked=0)
    assert second["events_processed"] == 0
    assert second["alerts_fired"] == 0
    assert second["verification_results"] == {}
