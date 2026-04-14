import sys

sys.path.insert(0, "attacker")

try:
    from scapy.all import DNS

    from bailiwick_inject import craft_bailiwick_injection_response
    from kaminsky_flood import craft_spoofed_response

    SCAPY_AVAILABLE = True
except ModuleNotFoundError:
    SCAPY_AVAILABLE = False


def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="ignore")
    return str(value)


if SCAPY_AVAILABLE:
    def test_craft_spoofed_response_has_answer_authority_and_glue() -> None:
        packet = craft_spoofed_response(
            resolver_ip="172.28.0.10",
            resolver_port=5300,
            auth_server_ip="198.41.0.4",
            query_name="rand1.example.com",
            spoofed_ip="6.6.6.6",
            txid=4242,
            delegated_ns="ns1.attacker.net",
            delegated_ns_ip="6.6.6.6",
        )

        dns = packet[DNS]
        assert packet.src == "198.41.0.4"
        assert packet.dst == "172.28.0.10"
        assert packet.dport == 5300
        assert dns.id == 4242
        assert dns.qr == 1
        assert dns.aa == 1
        assert _text(dns.qd.qname) == "rand1.example.com."
        assert dns.an.rdata == "6.6.6.6"
        assert _text(dns.ns.rrname) == "example.com."
        assert _text(dns.ns.rdata) == "ns1.attacker.net."
        assert _text(dns.ar.rrname) == "ns1.attacker.net."
        assert dns.ar.rdata == "6.6.6.6"


    def test_craft_bailiwick_injection_response_has_unrelated_additional_record() -> None:
        packet = craft_bailiwick_injection_response(
            resolver_ip="172.28.0.10",
            resolver_port=5300,
            auth_server_ip="198.41.0.4",
            query_name="example.com",
            answer_ip="93.184.216.34",
            injected_name="bankofamerica.com",
            injected_ip="6.6.6.6",
            txid=5150,
        )

        dns = packet[DNS]
        assert packet.src == "198.41.0.4"
        assert packet.dst == "172.28.0.10"
        assert packet.dport == 5300
        assert dns.id == 5150
        assert dns.qr == 1
        assert dns.aa == 1
        assert _text(dns.qd.qname) == "example.com."
        assert dns.an.rdata == "93.184.216.34"
        assert _text(dns.ar.rrname) == "bankofamerica.com."
        assert dns.ar.rdata == "6.6.6.6"
