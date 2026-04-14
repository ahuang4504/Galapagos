from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, "detector/src")

from heuristics.query_response import QueryResponseMatcher
from models import DNSEvent


def make_event(
    *,
    event_type: str,
    message_type: str,
    timestamp: datetime,
    query_name: str = "example.com",
    query_type: str = "A",
    transaction_id: int = 1234,
    source_ip: str = "172.28.0.10",
    source_port: int = 5300,
    dest_ip: str = "198.41.0.4",
    dest_port: int = 53,
    response_code: str | None = None,
    answers: list | None = None,
) -> DNSEvent:
    return DNSEvent(
        timestamp=timestamp,
        event_type=event_type,
        message_type=message_type,
        query_name=query_name,
        query_type=query_type,
        transaction_id=transaction_id,
        source_ip=source_ip,
        source_port=source_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        response_code=response_code,
        answers=answers or [],
    )


def test_normal_query_then_response_has_no_alerts_and_expires() -> None:
    matcher = QueryResponseMatcher(query_timeout_seconds=10, duplicate_grace_seconds=2)
    now = datetime.now(timezone.utc)

    query = make_event(
        event_type="query",
        message_type="resolver_query",
        timestamp=now,
    )
    response = make_event(
        event_type="response",
        message_type="resolver_response",
        timestamp=now + timedelta(milliseconds=100),
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
        answers=[("example.com", "A", 300, "93.184.216.34")],
    )
    cleanup_probe = make_event(
        event_type="query",
        message_type="client_query",
        timestamp=now + timedelta(seconds=3),
    )

    assert matcher.process_event(query) == []
    assert matcher.process_event(response) == []
    assert len(matcher.pending_queries) == 1

    matcher.process_event(cleanup_probe)
    assert matcher.pending_queries == {}


def test_unsolicited_response_triggers_alert() -> None:
    matcher = QueryResponseMatcher(startup_grace_seconds=0)
    now = datetime.now(timezone.utc)

    response = make_event(
        event_type="response",
        message_type="resolver_response",
        timestamp=now,
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
    )

    alerts = matcher.process_event(response)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "unsolicited_response"
    assert alerts[0]["txid"] == 1234


def test_startup_grace_suppresses_initial_unsolicited_response() -> None:
    matcher = QueryResponseMatcher(startup_grace_seconds=2)
    now = datetime.now(timezone.utc)

    response = make_event(
        event_type="response",
        message_type="resolver_response",
        timestamp=now,
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
    )

    assert matcher.process_event(response) == []


def test_resolver_response_without_question_metadata_is_ignored() -> None:
    matcher = QueryResponseMatcher()
    now = datetime.now(timezone.utc)

    response = make_event(
        event_type="response",
        message_type="resolver_response",
        timestamp=now,
        query_name="",
        query_type="",
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
    )

    assert matcher.process_event(response) == []


def test_duplicate_response_triggers_single_alert() -> None:
    matcher = QueryResponseMatcher(duplicate_grace_seconds=2)
    now = datetime.now(timezone.utc)

    query = make_event(
        event_type="query",
        message_type="resolver_query",
        timestamp=now,
    )
    first_response = make_event(
        event_type="response",
        message_type="resolver_response",
        timestamp=now + timedelta(milliseconds=100),
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
        answers=[("example.com", "A", 300, "93.184.216.34")],
    )
    second_response = make_event(
        event_type="response",
        message_type="resolver_response",
        timestamp=now + timedelta(milliseconds=200),
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
        answers=[("example.com", "A", 300, "203.0.113.99")],
    )

    assert matcher.process_event(query) == []
    assert matcher.process_event(first_response) == []

    alerts = matcher.process_event(second_response)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "duplicate_response"
    assert alerts[0]["first_answer"] == [("example.com", "A", 300, "93.184.216.34")]
    assert alerts[0]["second_answer"] == [("example.com", "A", 300, "203.0.113.99")]

    assert matcher.process_event(second_response) == []


def test_stale_pending_query_is_removed_after_timeout() -> None:
    matcher = QueryResponseMatcher(query_timeout_seconds=10, duplicate_grace_seconds=2)
    now = datetime.now(timezone.utc)

    query = make_event(
        event_type="query",
        message_type="resolver_query",
        timestamp=now,
    )
    late_probe = make_event(
        event_type="response",
        message_type="resolver_response",
        timestamp=now + timedelta(seconds=11),
        transaction_id=9999,
    )

    matcher.process_event(query)
    assert len(matcher.pending_queries) == 1

    matcher.process_event(late_probe)
    assert matcher.pending_queries == {}
