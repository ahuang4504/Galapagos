from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, "detector/src")

from models import DNSEvent
from resolver_confirmation import ResolverConfirmationTracker


def make_event(
    *,
    timestamp: datetime,
    message_type: str,
    query_name: str = "example.com",
) -> DNSEvent:
    return DNSEvent(
        timestamp=timestamp,
        event_type="response",
        message_type=message_type,
        query_name=query_name,
        query_type="A",
        transaction_id=1234,
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
        answers=[("example.com", "A", 300, "93.184.216.34")],
        sensor="dnstap",
    )


def test_confirmation_tracker_returns_recent_resolver_evidence() -> None:
    tracker = ResolverConfirmationTracker(retention_seconds=30)
    now = datetime.now(timezone.utc)
    tracker.process_event(make_event(timestamp=now, message_type="resolver_response"))
    tracker.process_event(make_event(timestamp=now + timedelta(seconds=1), message_type="client_response"))

    confirmation = tracker.confirm_for_alert({"domain": "example.com"}, now + timedelta(seconds=2))

    assert confirmation is not None
    assert confirmation["resolver_response_seen"] is True
    assert confirmation["client_response_seen"] is True
    assert confirmation["matched_domains"] == ["example.com"]


def test_confirmation_tracker_uses_query_domain_fallback() -> None:
    tracker = ResolverConfirmationTracker(retention_seconds=30)
    now = datetime.now(timezone.utc)
    tracker.process_event(make_event(timestamp=now, message_type="resolver_response", query_name="example.com"))

    confirmation = tracker.confirm_for_alert(
        {"alert_type": "bailiwick_violation", "domain": "bankofamerica.com", "query_domain": "example.com"},
        now + timedelta(seconds=1),
    )

    assert confirmation is not None
    assert confirmation["latest_domain"] == "example.com"


def test_confirmation_tracker_expires_old_events() -> None:
    tracker = ResolverConfirmationTracker(retention_seconds=1)
    now = datetime.now(timezone.utc)
    tracker.process_event(make_event(timestamp=now, message_type="resolver_response"))

    confirmation = tracker.confirm_for_alert({"domain": "example.com"}, now + timedelta(seconds=3))

    assert confirmation is None
