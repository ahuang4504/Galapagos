import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, "scripts")

from parse_detector_log import parse_detector_log


def test_parse_detector_log_summarizes_alerts_and_summaries() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "detector.log"
        path.write_text(
            json.dumps(
                {
                    "type": "summary",
                    "interval_seconds": 60,
                    "events_processed": 10,
                    "queries_tracked": 2,
                    "alerts_fired": 0,
                    "verification_results": {},
                    "logged_at": "2026-04-11T00:00:01+00:00",
                }
            )
            + "\n"
            + json.dumps(
                {
                    "alert_type": "kaminsky_precursor",
                    "domain": "example.com",
                    "verification": {"status": "MATCH"},
                    "logged_at": "2026-04-11T00:00:05+00:00",
                }
            )
            + "\n"
            + json.dumps(
                {
                    "alert_type": "duplicate_response",
                    "domain": "example.com",
                    "verification": {"status": "CONFIRMED"},
                    "logged_at": "2026-04-11T00:00:07+00:00",
                }
            )
            + "\n"
        )

        summary = parse_detector_log(path, start_time="2026-04-11T00:00:00+00:00")

    assert summary["alert_counts"] == {
        "duplicate_response": 1,
        "kaminsky_precursor": 1,
    }
    assert summary["verification_counts"] == {"CONFIRMED": 1, "MATCH": 1}
    assert summary["total_events_processed"] == 10
    assert summary["total_summary_alerts"] == 0
    assert summary["first_alert_logged_at"] == "2026-04-11T00:00:05+00:00"
    assert summary["first_alert_latency_seconds"] == 5.0
