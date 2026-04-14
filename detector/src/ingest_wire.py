import asyncio
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator

import dns.rcode
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, AsyncSniffer

from models import DNSEvent


logger = logging.getLogger(__name__)

RESOLVER_IP = "172.28.0.10"
DNS_PORT = 53


def _normalize_name(name) -> str:
    if name is None:
        return ""
    if isinstance(name, bytes):
        name = name.decode(errors="ignore")
    return str(name).rstrip(".").lower().strip()


def _qtype_to_text(value) -> str:
    if isinstance(value, bytes):
        value = value.decode(errors="ignore")
    if isinstance(value, str):
        return value.upper()

    mapping = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        39: "DNAME",
    }
    return mapping.get(int(value), str(value))


def _rdata_to_text(rr: DNSRR) -> str:
    value = rr.rdata
    if isinstance(value, bytes):
        return value.decode(errors="ignore").rstrip(".")
    return str(value).rstrip(".")


def _extract_rrs(section, count: int) -> list[tuple[str, str, int, str]]:
    records = []
    if section is None or count <= 0:
        return records

    try:
        rr_items = list(section)
    except TypeError:
        rr_items = None

    if rr_items:
        for rr in rr_items[:count]:
            if not isinstance(rr, DNSRR):
                continue
            records.append(
                (
                    _normalize_name(rr.rrname),
                    _qtype_to_text(rr.type),
                    int(getattr(rr, "ttl", 0)),
                    _rdata_to_text(rr),
                )
            )
        return records

    current = section
    for _ in range(count):
        if not isinstance(current, DNSRR):
            break
        records.append(
            (
                _normalize_name(current.rrname),
                _qtype_to_text(current.type),
                int(getattr(current, "ttl", 0)),
                _rdata_to_text(current),
            )
        )
        current = current.payload
    return records


def _packet_to_event(packet, resolver_ip: str = RESOLVER_IP) -> DNSEvent | None:
    if not (
        packet.haslayer(IP)
        and packet.haslayer(UDP)
        and packet.haslayer(DNS)
        and packet.haslayer(DNSQR)
    ):
        return None

    ip = packet[IP]
    udp = packet[UDP]
    dns_layer = packet[DNS]
    qd = dns_layer[DNSQR]

    if dns_layer.qr == 0:
        event_type = "query"
        if ip.src == resolver_ip and udp.dport == 53:
            message_type = "resolver_query"
        elif ip.dst == resolver_ip and udp.dport == 53:
            message_type = "client_query"
        else:
            return None
    else:
        event_type = "response"
        if ip.dst == resolver_ip and udp.sport == 53:
            message_type = "resolver_response"
        elif ip.src == resolver_ip and udp.sport == 53:
            message_type = "client_response"
        else:
            return None

    answers = _extract_rrs(dns_layer.an, int(getattr(dns_layer, "ancount", 0))) if dns_layer.qr else []
    authority = _extract_rrs(dns_layer.ns, int(getattr(dns_layer, "nscount", 0))) if dns_layer.qr else []
    additional = _extract_rrs(dns_layer.ar, int(getattr(dns_layer, "arcount", 0))) if dns_layer.qr else []

    return DNSEvent(
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        message_type=message_type,
        query_name=_normalize_name(qd.qname),
        query_type=_qtype_to_text(qd.qtype),
        transaction_id=int(dns_layer.id),
        source_ip=ip.src,
        source_port=int(udp.sport),
        dest_ip=ip.dst,
        dest_port=int(udp.dport),
        response_code=dns.rcode.to_text(int(dns_layer.rcode)) if dns_layer.qr else None,
        answers=answers,
        authority=authority,
        additional=additional,
        sensor="wire",
    )


def _is_dns_udp_packet(packet) -> bool:
    return packet.haslayer(UDP) and (
        int(packet[UDP].sport) == DNS_PORT or int(packet[UDP].dport) == DNS_PORT
    )


async def ingest_events(
    *,
    interface: str,
    resolver_ip: str = RESOLVER_IP,
) -> AsyncGenerator[DNSEvent, None]:
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[DNSEvent] = asyncio.Queue(maxsize=10_000)

    def push_event(event: DNSEvent) -> None:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("wire queue full, dropping %s/%s", event.event_type, event.query_name)

    def handle_packet(packet) -> None:
        event = _packet_to_event(packet, resolver_ip=resolver_ip)
        if event is None:
            return
        loop.call_soon_threadsafe(push_event, event)

    sniffer = AsyncSniffer(
        iface=interface,
        lfilter=_is_dns_udp_packet,
        prn=handle_packet,
        store=False,
    )
    logger.info(
        "wire: starting packet capture on %s with python-side UDP/53 filter",
        interface,
    )
    sniffer.start()

    try:
        while True:
            yield await queue.get()
    finally:
        logger.info("wire: stopping packet capture on %s", interface)
        sniffer.stop()
