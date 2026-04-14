import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.rcode
import dns.resolver
import httpx


CLOUDFLARE_DOH_URL = os.getenv(
    "CLOUDFLARE_DOH_URL",
    "https://cloudflare-dns.com/dns-query",
)
GOOGLE_DOH_URL = os.getenv(
    "GOOGLE_DOH_URL",
    "https://dns.google/resolve",
)
LOCAL_RESOLVER_IP = os.getenv("LOCAL_RESOLVER_IP", "172.28.0.10")


@dataclass
class ResolverLookup:
    answers: list[str]
    rcode: str


@dataclass
class VerificationResult:
    status: str
    domain: str
    local_answer: list[str]
    trusted_answers: dict[str, list[str]]
    local_rcode: str
    trusted_rcodes: dict[str, str]
    verified_at: str
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "status": self.status,
            "domain": self.domain,
            "local_answer": self.local_answer,
            "trusted_answers": self.trusted_answers,
            "local_rcode": self.local_rcode,
            "trusted_rcodes": self.trusted_rcodes,
            "verified_at": self.verified_at,
        }
        if self.reason:
            payload["reason"] = self.reason
        return payload


async def query_doh(
    domain: str,
    resolver_url: str,
    client: httpx.AsyncClient | None = None,
) -> ResolverLookup:
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=5.0, follow_redirects=True)

    headers = {}
    if "cloudflare-dns.com" in resolver_url:
        headers["Accept"] = "application/dns-json"

    try:
        response = await client.get(
            resolver_url,
            params={"name": domain, "type": "A"},
            headers=headers,
        )
        response.raise_for_status()
        payload = response.json()
        rcode_value = int(payload.get("Status", 0))
        answers = [
            answer["data"]
            for answer in payload.get("Answer", [])
            if answer.get("type") == 1 and "data" in answer
        ]
        return ResolverLookup(
            answers=answers,
            rcode=dns.rcode.to_text(rcode_value),
        )
    finally:
        if owns_client:
            await client.aclose()


def query_local_resolver(domain: str, resolver_ip: str) -> ResolverLookup:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    try:
        answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return ResolverLookup(answers=[], rcode="NXDOMAIN")
    except dns.resolver.NoAnswer:
        return ResolverLookup(answers=[], rcode="NOERROR")
    except dns.exception.DNSException as exc:
        raise RuntimeError(f"local resolver query failed: {exc}") from exc

    return ResolverLookup(
        answers=[item.address for item in answer],
        rcode=dns.rcode.to_text(answer.response.rcode()),
    )


async def verify_domain(
    domain: str,
    local_resolver_ip: str = LOCAL_RESOLVER_IP,
    *,
    cloudflare_url: str = CLOUDFLARE_DOH_URL,
    google_url: str = GOOGLE_DOH_URL,
) -> VerificationResult:
    normalized = domain.rstrip(".").lower()
    verified_at = datetime.now(timezone.utc).isoformat()

    try:
        local_lookup = query_local_resolver(normalized, local_resolver_ip)
    except Exception as exc:
        return VerificationResult(
            status="VERIFICATION_FAILED",
            domain=normalized,
            local_answer=[],
            trusted_answers={"cloudflare": [], "google": []},
            local_rcode="UNKNOWN",
            trusted_rcodes={"cloudflare": "UNKNOWN", "google": "UNKNOWN"},
            verified_at=verified_at,
            reason=str(exc),
        )

    try:
        cloudflare_lookup, google_lookup = await asyncio.gather(
            query_doh(normalized, cloudflare_url),
            query_doh(normalized, google_url),
        )
    except Exception as exc:
        return VerificationResult(
            status="VERIFICATION_FAILED",
            domain=normalized,
            local_answer=local_lookup.answers,
            trusted_answers={"cloudflare": [], "google": []},
            local_rcode=local_lookup.rcode,
            trusted_rcodes={"cloudflare": "UNKNOWN", "google": "UNKNOWN"},
            verified_at=verified_at,
            reason=str(exc),
        )

    trusted_answers = {
        "cloudflare": cloudflare_lookup.answers,
        "google": google_lookup.answers,
    }
    trusted_rcodes = {
        "cloudflare": cloudflare_lookup.rcode,
        "google": google_lookup.rcode,
    }

    if local_lookup.rcode == "NXDOMAIN":
        status = (
            "MATCH"
            if cloudflare_lookup.rcode == "NXDOMAIN" and google_lookup.rcode == "NXDOMAIN"
            else "CONFIRMED"
        )
    else:
        trusted_union = set(cloudflare_lookup.answers) | set(google_lookup.answers)
        local_answers = set(local_lookup.answers)
        status = "MATCH" if local_answers.issubset(trusted_union) else "CONFIRMED"

    return VerificationResult(
        status=status,
        domain=normalized,
        local_answer=local_lookup.answers,
        trusted_answers=trusted_answers,
        local_rcode=local_lookup.rcode,
        trusted_rcodes=trusted_rcodes,
        verified_at=verified_at,
    )


class ActiveVerifier:
    def __init__(
        self,
        local_resolver_ip: str = LOCAL_RESOLVER_IP,
        cooldown_seconds: int = 30,
        verifier=verify_domain,
    ) -> None:
        self.local_resolver_ip = local_resolver_ip
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.verifier = verifier
        self.cache: dict[str, tuple[datetime, VerificationResult]] = {}

    async def verify(self, domain: str) -> VerificationResult:
        normalized = domain.rstrip(".").lower()
        now = datetime.now(timezone.utc)
        cached = self.cache.get(normalized)
        if cached and now - cached[0] <= self.cooldown:
            return cached[1]

        result = await self.verifier(normalized, self.local_resolver_ip)
        self.cache[normalized] = (now, result)
        return result


def extract_alert_domain(alert: dict[str, object]) -> str | None:
    alert_type = alert.get("alert_type")
    if alert_type == "kaminsky_precursor":
        domain = alert.get("target_domain")
    elif alert_type == "bailiwick_violation":
        record = alert.get("violating_record", {})
        if isinstance(record, dict) and record.get("type") in {"A", "AAAA"}:
            domain = record.get("name")
        else:
            domain = alert.get("query_domain")
    else:
        domain = alert.get("domain")

    if isinstance(domain, str) and domain.strip():
        return domain.rstrip(".").lower()
    return None
