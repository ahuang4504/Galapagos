from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, "detector/src")

from heuristics.cusum import CUSUMConfig, CUSUMHeuristic
from models import DNSEvent


def make_event(
    *,
    timestamp: datetime,
    event_type: str,
    message_type: str,
    query_name: str = "example.com",
    query_type: str = "A",
    transaction_id: int = 1234,
    source_ip: str = "172.28.0.10",
    source_port: int = 5300,
    dest_ip: str = "198.41.0.4",
    dest_port: int = 53,
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
        response_code="NOERROR" if event_type == "response" else None,
        answers=answers or [],
    )


def test_stationary_ttl_signal_stays_quiet_after_warmup() -> None:
    heuristic = CUSUMHeuristic(
        feature_configs={
            "ttl": CUSUMConfig(warmup_n=3, k_sigma=0.5, h_sigma=5.0, cooldown_seconds=0.0)
        }
    )
    now = datetime.now(timezone.utc)

    alerts = []
    for idx in range(6):
        response = make_event(
            timestamp=now + timedelta(seconds=idx),
            event_type="response",
            message_type="resolver_response",
            answers=[("example.com", "A", 300, "93.184.216.34")],
        )
        alerts.extend(heuristic.process_event(response))

    assert alerts == []


def test_ttl_shift_triggers_cusum_alert() -> None:
    heuristic = CUSUMHeuristic(
        feature_configs={
            "ttl": CUSUMConfig(warmup_n=3, k_sigma=0.1, h_sigma=1.0, cooldown_seconds=0.0)
        }
    )
    now = datetime.now(timezone.utc)

    alerts = []
    stable_ttls = [300, 300, 300, 300]
    shifted_ttls = [7200, 7200, 7200]
    for idx, ttl in enumerate(stable_ttls + shifted_ttls):
        response = make_event(
            timestamp=now + timedelta(seconds=idx),
            event_type="response",
            message_type="resolver_response",
            answers=[("example.com", "A", ttl, "93.184.216.34")],
        )
        alerts.extend(heuristic.process_event(response))

    assert alerts
    assert alerts[0]["alert_type"] == "cusum_change_point"
    assert alerts[0]["feature"] == "ttl"
    assert alerts[0]["direction"] == "upward_shift"


def test_rtt_shift_triggers_alert_with_matched_query() -> None:
    heuristic = CUSUMHeuristic(
        feature_configs={
            "rtt_ms": CUSUMConfig(warmup_n=3, k_sigma=0.1, h_sigma=1.0, cooldown_seconds=0.0)
        }
    )
    now = datetime.now(timezone.utc)
    alerts = []

    stable_rtts = [50, 50, 50, 50]
    shifted_rtts = [5, 5, 5]
    for idx, rtt_ms in enumerate(stable_rtts + shifted_rtts):
        query_time = now + timedelta(seconds=idx * 2)
        response_time = query_time + timedelta(milliseconds=rtt_ms)
        query = make_event(
            timestamp=query_time,
            event_type="query",
            message_type="resolver_query",
            transaction_id=2000 + idx,
        )
        response = make_event(
            timestamp=response_time,
            event_type="response",
            message_type="resolver_response",
            transaction_id=2000 + idx,
            source_ip="198.41.0.4",
            source_port=53,
            dest_ip="172.28.0.10",
            dest_port=5300,
        )
        alerts.extend(heuristic.process_event(query))
        alerts.extend(heuristic.process_event(response))

    assert alerts
    assert alerts[0]["feature"] == "rtt_ms"
    assert alerts[0]["direction"] == "downward_shift"


def test_non_resolver_events_are_ignored() -> None:
    heuristic = CUSUMHeuristic()
    now = datetime.now(timezone.utc)

    client_query = make_event(
        timestamp=now,
        event_type="query",
        message_type="client_query",
    )
    client_response = make_event(
        timestamp=now + timedelta(milliseconds=10),
        event_type="response",
        message_type="client_response",
        source_ip="172.28.0.10",
        source_port=53,
        dest_ip="172.28.0.20",
        dest_port=40000,
    )

    assert heuristic.process_event(client_query) == []
    assert heuristic.process_event(client_response) == []
