import sys

sys.path.insert(0, "attacker")

try:
    from attack_utils import (
        extract_parent_domain,
        random_subdomain,
        resolve_authoritative_server_ip,
    )
    from bailiwick_inject import build_parser as build_bailiwick_parser
    from kaminsky_flood import build_parser as build_kaminsky_parser

    IMPORTS_AVAILABLE = True
except ModuleNotFoundError:
    IMPORTS_AVAILABLE = False


if IMPORTS_AVAILABLE:
    def test_extract_parent_domain_handles_deep_names() -> None:
        assert extract_parent_domain("a.b.c.example.com") == "example.com"
        assert extract_parent_domain("example.com") == "example.com"


    def test_random_subdomain_stays_under_target_domain() -> None:
        value = random_subdomain("Example.COM")
        assert value.endswith(".example.com")
        assert value != "example.com"


    def test_resolve_authoritative_server_ip_uses_ns_and_a_lookups(monkeypatch) -> None:
        class FakeNS:
            def __init__(self, target: str) -> None:
                self.target = target


        class FakeA:
            def __init__(self, ip: str) -> None:
                self._ip = ip

            def to_text(self) -> str:
                return self._ip


        class FakeResolver:
            def __init__(self, configure: bool = True) -> None:
                self.nameservers = []

            def resolve(self, name: str, record_type: str):
                if (name, record_type) == ("example.com", "NS"):
                    return [FakeNS("ns1.example.net.")]
                if (name, record_type) == ("ns1.example.net", "A"):
                    return [FakeA("198.51.100.20")]
                raise AssertionError(f"unexpected lookup: {(name, record_type)}")


        import attack_utils

        monkeypatch.setattr(attack_utils.dns.resolver, "Resolver", FakeResolver)

        result = resolve_authoritative_server_ip("a.example.com")
        assert result == {
            "zone": "example.com",
            "ns_name": "ns1.example.net",
            "auth_server_ip": "198.51.100.20",
        }


    def test_attack_parsers_default_to_lab_friendly_settings() -> None:
        kaminsky_args = build_kaminsky_parser().parse_args(["--target-domain", "example.com"])
        bailiwick_args = build_bailiwick_parser().parse_args([])

        assert kaminsky_args.default_resolver_port == 5300
        assert kaminsky_args.discover is False
        assert bailiwick_args.default_resolver_port == 5300
        assert bailiwick_args.randomize_query_name is True
        assert bailiwick_args.discover is False
