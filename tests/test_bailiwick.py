from datetime import datetime, timezone
import sys

sys.path.insert(0, "detector/src")

from heuristics.bailiwick import (
    BailiwickEnforcer,
    extract_bailiwick_zone,
    is_in_bailiwick,
)
from models import DNSEvent


def make_response_event(
    *,
    query_name: str,
    authority: list | None = None,
    additional: list | None = None,
    message_type: str = "resolver_response",
    event_type: str = "response",
) -> DNSEvent:
    return DNSEvent(
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        message_type=message_type,
        query_name=query_name,
        query_type="A",
        transaction_id=1234,
        source_ip="198.41.0.4",
        source_port=53,
        dest_ip="172.28.0.10",
        dest_port=5300,
        response_code="NOERROR",
        authority=authority or [],
        additional=additional or [],
    )


def test_extract_bailiwick_zone_examples() -> None:
    assert extract_bailiwick_zone("www.google.com") == "google.com"
    assert extract_bailiwick_zone("mail.sub.example.org") == "example.org"
    assert extract_bailiwick_zone("example.com.") == "example.com"


def test_is_in_bailiwick_examples() -> None:
    assert is_in_bailiwick("google.com", "google.com")
    assert is_in_bailiwick("ns1.google.com", "google.com")
    assert not is_in_bailiwick("bankofamerica.com", "example.com")
    assert not is_in_bailiwick("ns1.attacker.net", "example.com")


def test_normal_in_bailiwick_records_do_not_alert() -> None:
    enforcer = BailiwickEnforcer()
    event = make_response_event(
        query_name="www.google.com",
        authority=[("google.com", "NS", 300, "ns1.google.com.")],
        additional=[("ns1.google.com", "A", 300, "8.8.8.8")],
    )

    assert enforcer.process_event(event) == []


def test_out_of_bailiwick_additional_owner_name_alerts() -> None:
    enforcer = BailiwickEnforcer()
    event = make_response_event(
        query_name="www.example.com",
        additional=[("bankofamerica.com", "A", 300, "6.6.6.6")],
    )

    alerts = enforcer.process_event(event)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "bailiwick_violation"
    assert alerts[0]["section"] == "additional"
    assert alerts[0]["violating_field"] == "name"
    assert alerts[0]["violating_value"] == "bankofamerica.com"


def test_out_of_bailiwick_ns_target_alerts() -> None:
    enforcer = BailiwickEnforcer()
    event = make_response_event(
        query_name="random.example.com",
        authority=[("example.com", "NS", 300, "ns1.attacker.net.")],
        additional=[("ns1.attacker.net", "A", 300, "6.6.6.6")],
    )

    assert enforcer.process_event(event) == []


def test_referenced_out_of_zone_glue_does_not_alert() -> None:
    enforcer = BailiwickEnforcer()
    event = make_response_event(
        query_name="www.gitlab.com",
        authority=[("gitlab.com", "NS", 300, "diva.ns.cloudflare.com.")],
        additional=[("diva.ns.cloudflare.com", "A", 300, "108.162.192.97")],
    )

    assert enforcer.process_event(event) == []


def test_parent_referral_authority_records_do_not_alert() -> None:
    enforcer = BailiwickEnforcer()
    event = make_response_event(
        query_name="ns1.bluecatdns.net",
        authority=[
            ("net", "NS", 172800, "a.gtld-servers.net."),
            ("net", "NS", 172800, "b.gtld-servers.net."),
        ],
    )

    assert enforcer.process_event(event) == []


def test_non_resolver_responses_are_ignored() -> None:
    enforcer = BailiwickEnforcer()
    client_event = make_response_event(
        query_name="www.example.com",
        additional=[("bankofamerica.com", "A", 300, "6.6.6.6")],
        message_type="client_response",
    )
    query_event = make_response_event(
        query_name="www.example.com",
        additional=[("bankofamerica.com", "A", 300, "6.6.6.6")],
        message_type="resolver_query",
        event_type="query",
    )

    assert enforcer.process_event(client_event) == []
    assert enforcer.process_event(query_event) == []
