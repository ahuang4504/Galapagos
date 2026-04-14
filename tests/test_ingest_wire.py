import sys

sys.path.insert(0, "detector/src")

try:
    from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

    from ingest_wire import _packet_to_event

    SCAPY_AVAILABLE = True
except ModuleNotFoundError:
    SCAPY_AVAILABLE = False


if SCAPY_AVAILABLE:
    def test_packet_to_event_maps_resolver_query() -> None:
        packet = (
            IP(src="172.28.0.10", dst="198.41.0.4")
            / UDP(sport=5300, dport=53)
            / DNS(id=4242, qr=0, qd=DNSQR(qname="rand1.example.com", qtype="A"))
        )

        event = _packet_to_event(packet)

        assert event is not None
        assert event.sensor == "wire"
        assert event.event_type == "query"
        assert event.message_type == "resolver_query"
        assert event.query_name == "rand1.example.com"
        assert event.query_type == "A"
        assert event.transaction_id == 4242
        assert event.source_port == 5300
        assert event.dest_port == 53


    def test_packet_to_event_maps_resolver_response_with_sections() -> None:
        packet = (
            IP(src="198.41.0.4", dst="172.28.0.10")
            / UDP(sport=53, dport=5300)
            / DNS(
                id=4242,
                qr=1,
                aa=1,
                rcode=0,
                qd=DNSQR(qname="rand1.example.com", qtype="A"),
                ancount=1,
                nscount=1,
                arcount=1,
                an=DNSRR(rrname="rand1.example.com", type="A", ttl=300, rdata="6.6.6.6"),
                ns=DNSRR(rrname="example.com", type="NS", ttl=300, rdata="ns1.attacker.net."),
                ar=DNSRR(rrname="ns1.attacker.net", type="A", ttl=300, rdata="6.6.6.6"),
            )
        )

        event = _packet_to_event(packet)

        assert event is not None
        assert event.sensor == "wire"
        assert event.event_type == "response"
        assert event.message_type == "resolver_response"
        assert event.query_name == "rand1.example.com"
        assert event.query_type == "A"
        assert event.response_code == "NOERROR"
        assert event.answers == [("rand1.example.com", "A", 300, "6.6.6.6")]
        assert event.authority == [("example.com", "NS", 300, "ns1.attacker.net")]
        assert event.additional == [("ns1.attacker.net", "A", 300, "6.6.6.6")]
