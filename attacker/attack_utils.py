import random
import string
import threading
import time
from typing import Any

import dns.message
import dns.query
import dns.resolver
from scapy.all import DNS, DNSQR, IP, UDP, sniff


def normalize_domain(name: str) -> str:
    return name.rstrip(".").lower().strip()


def fqdn(name: str) -> str:
    normalized = normalize_domain(name)
    return f"{normalized}." if normalized else ""


def extract_parent_domain(query_name: str) -> str:
    normalized = normalize_domain(query_name)
    labels = [label for label in normalized.split(".") if label]

    if len(labels) <= 2:
        return normalized

    return ".".join(labels[-2:])


def random_subdomain(target_domain: str, length: int = 8) -> str:
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{label}.{normalize_domain(target_domain)}"


def resolve_authoritative_server_ip(
    query_name: str,
    bootstrap_resolver: str | None = None,
) -> dict[str, str]:
    zone = extract_parent_domain(query_name)
    resolver = dns.resolver.Resolver(configure=True)
    if bootstrap_resolver:
        resolver.nameservers = [bootstrap_resolver]

    ns_answers = resolver.resolve(zone, "NS")
    for ns_rdata in ns_answers:
        ns_name = normalize_domain(str(ns_rdata.target))
        try:
            a_answers = resolver.resolve(ns_name, "A")
        except Exception:
            continue

        for a_rdata in a_answers:
            auth_ip = a_rdata.to_text()
            if auth_ip:
                return {
                    "zone": zone,
                    "ns_name": ns_name,
                    "auth_server_ip": auth_ip,
                }

    raise RuntimeError(f"could not resolve an IPv4 authoritative server for {zone}")


def trigger_resolver_query(query_name: str, resolver_ip: str, timeout: float = 1.0) -> None:
    message = dns.message.make_query(normalize_domain(query_name), "A")
    try:
        dns.query.udp(message, resolver_ip, timeout=timeout, ignore_unexpected=True)
    except Exception:
        # Timeouts and DNS failures are fine here; the point is to trigger recursion.
        pass


def discover_query_context(
    query_name: str,
    resolver_ip: str,
    iface: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    expected_name = normalize_domain(query_name)

    def fire_query() -> None:
        time.sleep(0.05)
        trigger_resolver_query(query_name, resolver_ip, timeout=timeout)

    worker = threading.Thread(target=fire_query, daemon=True)
    worker.start()
    packets = sniff(
        iface=iface,
        timeout=timeout,
        count=1,
        store=True,
        lfilter=lambda pkt: _matches_query(pkt, expected_name, resolver_ip),
    )
    worker.join(timeout=timeout)

    if not packets:
        raise RuntimeError(
            f"did not observe resolver query for {expected_name} within {timeout:.1f}s"
        )

    packet = packets[0]
    return {
        "query_name": expected_name,
        "auth_server_ip": packet[IP].dst,
        "resolver_port": packet[UDP].sport,
        "txid": packet[DNS].id,
    }


def _matches_query(packet, expected_name: str, resolver_ip: str) -> bool:
    if not (
        packet.haslayer(IP)
        and packet.haslayer(UDP)
        and packet.haslayer(DNS)
        and packet.haslayer(DNSQR)
    ):
        return False

    dns_layer = packet[DNS]
    if dns_layer.qr != 0 or packet[UDP].dport != 53 or packet[IP].src != resolver_ip:
        return False

    qname = dns_layer[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode(errors="ignore")

    return normalize_domain(str(qname)) == expected_name
