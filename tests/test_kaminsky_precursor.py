from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, "detector/src")

from heuristics.kaminsky_precursor import (
    KaminskyPrecursorDetector,
    extract_parent_domain,
    is_attack_like_query,
)
from models import DNSEvent


def make_event(
    *,
    timestamp: datetime,
    query_name: str,
    message_type: str = "resolver_query",
    event_type: str = "query",
) -> DNSEvent:
    return DNSEvent(
        timestamp=timestamp,
        event_type=event_type,
        message_type=message_type,
        query_name=query_name,
        query_type="A",
        transaction_id=1234,
        source_ip="172.28.0.10",
        source_port=5300,
        dest_ip="198.41.0.4",
        dest_port=53,
    )


def test_extract_parent_domain_examples() -> None:
    assert extract_parent_domain("google.com") == "google.com"
    assert extract_parent_domain("abc123.bankofamerica.com") == "bankofamerica.com"
    assert extract_parent_domain("a.b.c.d.example.com") == "example.com"
    assert extract_parent_domain("example.com.") == "example.com"


def test_normal_traffic_does_not_trigger_alert() -> None:
    detector = KaminskyPrecursorDetector(threshold=5, window_seconds=30, cooldown_seconds=60)
    now = datetime.now(timezone.utc)

    events = [
        make_event(timestamp=now + timedelta(seconds=idx), query_name=name)
        for idx, name in enumerate(
            [
                "www.google.com",
                "mail.google.com",
                "docs.google.com",
                "api.example.com",
                "shop.example.com",
            ]
        )
    ]

    alerts = []
    for event in events:
        alerts.extend(detector.process_event(event))

    assert alerts == []


def test_attack_like_query_filter_examples() -> None:
    assert is_attack_like_query("abc123xy.example.com")
    assert is_attack_like_query("a1b2c3d4.example.com")
    assert not is_attack_like_query("www.example.com")
    assert not is_attack_like_query("ns1.fastly.net")
    assert not is_attack_like_query("bigred.cit.cornell.edu")
    assert not is_attack_like_query("awsdns-11.co.uk")


def test_threshold_crossing_triggers_alert() -> None:
    detector = KaminskyPrecursorDetector(threshold=3, window_seconds=30, cooldown_seconds=60)
    now = datetime.now(timezone.utc)

    alerts = []
    for idx in range(4):
        event = make_event(
            timestamp=now + timedelta(seconds=idx),
            query_name=f"abc1234{idx}.example.com",
        )
        alerts.extend(detector.process_event(event))

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "kaminsky_precursor"
    assert alerts[0]["target_domain"] == "example.com"
    assert alerts[0]["unique_subdomains_count"] == 4


def test_cooldown_suppresses_repeat_alerts() -> None:
    detector = KaminskyPrecursorDetector(threshold=2, window_seconds=30, cooldown_seconds=60)
    now = datetime.now(timezone.utc)

    first_batch = [
        make_event(timestamp=now + timedelta(seconds=idx), query_name=f"abc1234{idx}.example.com")
        for idx in range(3)
    ]
    second_batch = [
        make_event(timestamp=now + timedelta(seconds=10 + idx), query_name=f"def5678{idx}.example.com")
        for idx in range(3)
    ]

    alerts = []
    for event in first_batch + second_batch:
        alerts.extend(detector.process_event(event))

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "kaminsky_precursor"


def test_new_window_after_expiry_can_alert_again() -> None:
    detector = KaminskyPrecursorDetector(threshold=2, window_seconds=5, cooldown_seconds=5)
    now = datetime.now(timezone.utc)

    first_batch = [
        make_event(timestamp=now + timedelta(seconds=idx), query_name=f"abc1234{idx}.example.com")
        for idx in range(3)
    ]
    second_batch = [
        make_event(timestamp=now + timedelta(seconds=10 + idx), query_name=f"def5678{idx}.example.com")
        for idx in range(3)
    ]

    alerts = []
    for event in first_batch + second_batch:
        alerts.extend(detector.process_event(event))

    assert len(alerts) == 2
    assert alerts[0]["target_domain"] == "example.com"
    assert alerts[1]["target_domain"] == "example.com"


def test_non_resolver_queries_are_ignored() -> None:
    detector = KaminskyPrecursorDetector(threshold=1, window_seconds=30, cooldown_seconds=60)
    now = datetime.now(timezone.utc)

    client_event = make_event(
        timestamp=now,
        query_name="rand0.example.com",
        message_type="client_query",
    )
    response_event = make_event(
        timestamp=now + timedelta(seconds=1),
        query_name="rand1.example.com",
        event_type="response",
        message_type="resolver_response",
    )

    assert detector.process_event(client_event) == []
    assert detector.process_event(response_event) == []
