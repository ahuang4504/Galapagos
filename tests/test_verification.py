import asyncio
import sys
import types

try:
    import dns  # noqa: F401
except ModuleNotFoundError:
    fake_dns = types.ModuleType("dns")
    fake_dns_exception = types.ModuleType("dns.exception")
    fake_dns_resolver = types.ModuleType("dns.resolver")
    fake_dns_rcode = types.ModuleType("dns.rcode")

    class FakeDNSException(Exception):
        pass

    class FakeNXDOMAIN(FakeDNSException):
        pass

    class FakeNoAnswer(FakeDNSException):
        pass

    class FakeResolver:
        def __init__(self, configure=False):
            self.nameservers = []
            self.timeout = 0.0
            self.lifetime = 0.0

        def resolve(self, domain, rdtype, raise_on_no_answer=False):
            raise FakeDNSException("fake resolver not configured for direct use")

    fake_dns_exception.DNSException = FakeDNSException
    fake_dns_resolver.Resolver = FakeResolver
    fake_dns_resolver.NXDOMAIN = FakeNXDOMAIN
    fake_dns_resolver.NoAnswer = FakeNoAnswer
    fake_dns_rcode.to_text = lambda value: {0: "NOERROR", 3: "NXDOMAIN"}.get(value, str(value))

    fake_dns.exception = fake_dns_exception
    fake_dns.resolver = fake_dns_resolver
    fake_dns.rcode = fake_dns_rcode

    sys.modules["dns"] = fake_dns
    sys.modules["dns.exception"] = fake_dns_exception
    sys.modules["dns.resolver"] = fake_dns_resolver
    sys.modules["dns.rcode"] = fake_dns_rcode

try:
    import httpx  # noqa: F401
except ModuleNotFoundError:
    fake_httpx = types.SimpleNamespace(
        AsyncClient=object,
        HTTPError=Exception,
        RequestError=Exception,
        HTTPStatusError=Exception,
    )
    sys.modules["httpx"] = fake_httpx

sys.path.insert(0, "detector/src")

from verification import ActiveVerifier, ResolverLookup, extract_alert_domain, query_doh, verify_domain


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class FakeAsyncClient:
    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = []

    async def get(self, url, params=None, headers=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        return FakeResponse(self.payload)

    async def aclose(self) -> None:
        return None


def test_query_doh_parses_a_answers() -> None:
    client = FakeAsyncClient(
        {
            "Status": 0,
            "Answer": [
                {"name": "example.com", "type": 1, "data": "93.184.216.34"},
                {"name": "example.com", "type": 5, "data": "alias.example.com"},
            ],
        }
    )

    result = asyncio.run(query_doh("example.com", "https://dns.google/resolve", client=client))
    assert result.rcode == "NOERROR"
    assert result.answers == ["93.184.216.34"]


def test_verify_domain_match_uses_union_of_trusted_answers() -> None:
    import verification

    original_local = verification.query_local_resolver
    original_doh = verification.query_doh
    try:
        verification.query_local_resolver = lambda domain, resolver_ip: ResolverLookup(
            answers=["93.184.216.34"],
            rcode="NOERROR",
        )

        async def fake_query_doh(domain: str, resolver_url: str, client=None) -> ResolverLookup:
            if "cloudflare" in resolver_url:
                return ResolverLookup(answers=["93.184.216.34"], rcode="NOERROR")
            return ResolverLookup(answers=["93.184.216.35"], rcode="NOERROR")

        verification.query_doh = fake_query_doh
        result = asyncio.run(verify_domain("example.com"))
    finally:
        verification.query_local_resolver = original_local
        verification.query_doh = original_doh

    assert result.status == "MATCH"
    assert result.local_answer == ["93.184.216.34"]
    assert result.trusted_answers["cloudflare"] == ["93.184.216.34"]
    assert result.trusted_answers["google"] == ["93.184.216.35"]


def test_verify_domain_divergence_returns_confirmed() -> None:
    import verification

    original_local = verification.query_local_resolver
    original_doh = verification.query_doh
    try:
        verification.query_local_resolver = lambda domain, resolver_ip: ResolverLookup(
            answers=["6.6.6.6"],
            rcode="NOERROR",
        )

        async def fake_query_doh(domain: str, resolver_url: str, client=None) -> ResolverLookup:
            return ResolverLookup(answers=["93.184.216.34"], rcode="NOERROR")

        verification.query_doh = fake_query_doh
        result = asyncio.run(verify_domain("example.com"))
    finally:
        verification.query_local_resolver = original_local
        verification.query_doh = original_doh

    assert result.status == "CONFIRMED"
    assert result.local_answer == ["6.6.6.6"]


def test_verify_domain_handles_nxdomain_match() -> None:
    import verification

    original_local = verification.query_local_resolver
    original_doh = verification.query_doh
    try:
        verification.query_local_resolver = lambda domain, resolver_ip: ResolverLookup(
            answers=[],
            rcode="NXDOMAIN",
        )

        async def fake_query_doh(domain: str, resolver_url: str, client=None) -> ResolverLookup:
            return ResolverLookup(answers=[], rcode="NXDOMAIN")

        verification.query_doh = fake_query_doh
        result = asyncio.run(verify_domain("missing.example"))
    finally:
        verification.query_local_resolver = original_local
        verification.query_doh = original_doh

    assert result.status == "MATCH"
    assert result.local_rcode == "NXDOMAIN"


def test_verify_domain_handles_doh_failure() -> None:
    import verification

    original_local = verification.query_local_resolver
    original_doh = verification.query_doh
    try:
        verification.query_local_resolver = lambda domain, resolver_ip: ResolverLookup(
            answers=["93.184.216.34"],
            rcode="NOERROR",
        )

        async def fake_query_doh(domain: str, resolver_url: str, client=None) -> ResolverLookup:
            raise RuntimeError("network down")

        verification.query_doh = fake_query_doh
        result = asyncio.run(verify_domain("example.com"))
    finally:
        verification.query_local_resolver = original_local
        verification.query_doh = original_doh

    assert result.status == "VERIFICATION_FAILED"
    assert "network down" in result.reason


def test_active_verifier_uses_cache() -> None:
    calls = []

    async def fake_verifier(domain: str, resolver_ip: str):
        calls.append((domain, resolver_ip))
        return types.SimpleNamespace(
            to_dict=lambda: {"status": "MATCH"},
            status="MATCH",
        )

    verifier = ActiveVerifier(local_resolver_ip="172.28.0.10", cooldown_seconds=30, verifier=fake_verifier)
    first = asyncio.run(verifier.verify("example.com"))
    second = asyncio.run(verifier.verify("example.com"))

    assert first.status == "MATCH"
    assert second.status == "MATCH"
    assert len(calls) == 1


def test_extract_alert_domain_prefers_bailiwick_a_record_name() -> None:
    alert = {
        "alert_type": "bailiwick_violation",
        "query_domain": "www.example.com",
        "violating_record": {
            "name": "bankofamerica.com",
            "type": "A",
            "ttl": 300,
            "rdata": "6.6.6.6",
        },
    }
    assert extract_alert_domain(alert) == "bankofamerica.com"
