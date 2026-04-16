#!/usr/bin/env python3
import json
import re
import subprocess
import time
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path


def extract_unique_field_values(text: str, field: str) -> list[str]:
    pattern = re.compile(rf"{re.escape(field)}=([^\s]+)")
    seen: set[str] = set()
    values: list[str] = []
    for match in pattern.finditer(text):
        value = match.group(1).strip().rstrip(".").lower()
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return values


def load_domains(attacker_log: str | None, field: str, extra_domains: list[str]) -> list[str]:
    domains: list[str] = []
    if attacker_log:
        text = Path(attacker_log).read_text() if Path(attacker_log).exists() else ""
        domains.extend(extract_unique_field_values(text, field))

    seen = set(domains)
    for domain in extra_domains:
        normalized = domain.strip().rstrip(".").lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        domains.append(normalized)
    return domains


def query_resolver(domain: str, resolver: str) -> list[str]:
    command = [
        "docker",
        "compose",
        "exec",
        "-T",
        "client",
        "dig",
        "+short",
        f"@{resolver}",
        domain,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return [token.strip() for token in result.stdout.split() if token.strip()]


@dataclass
class AttackSuccessConfig:
    expected_ip: str
    resolver: str = "172.28.0.10"
    sample_count: int = 3
    sample_delay_seconds: float = 1.0
    attacker_log: str | None = None
    field: str = "qname"
    domains: list[str] = dataclass_field(default_factory=list)


def evaluate_domains(
    domains: list[str],
    *,
    expected_ip: str,
    resolver: str,
    sample_count: int,
    sample_delay_seconds: float,
) -> dict[str, object]:
    domain_results: list[dict[str, object]] = []
    successful_candidates = 0

    for domain in domains:
        samples: list[dict[str, object]] = []
        matched_samples = 0
        for sample_index in range(sample_count):
            answers = query_resolver(domain, resolver)
            matched = expected_ip in answers
            if matched:
                matched_samples += 1
            samples.append(
                {
                    "sample": sample_index + 1,
                    "answers": answers,
                    "matched_expected_ip": matched,
                }
            )
            if sample_index < sample_count - 1 and sample_delay_seconds > 0:
                time.sleep(sample_delay_seconds)

        success = sample_count > 0 and matched_samples == sample_count
        if success:
            successful_candidates += 1

        domain_results.append(
            {
                "domain": domain,
                "matched_samples": matched_samples,
                "sample_count": sample_count,
                "success": success,
                "samples": samples,
            }
        )

    total_candidates = len(domains)
    attack_success_rate = (
        successful_candidates / total_candidates if total_candidates else None
    )
    return {
        "expected_ip": expected_ip,
        "resolver": resolver,
        "sample_count": sample_count,
        "total_candidates": total_candidates,
        "successful_candidates": successful_candidates,
        "attack_success_rate": attack_success_rate,
        "cache_poisoned": successful_candidates > 0,
        "domains": domain_results,
    }


def measure_attack_success(config: AttackSuccessConfig) -> dict[str, object]:
    domains = load_domains(config.attacker_log, config.field, config.domains)
    return evaluate_domains(
        domains,
        expected_ip=config.expected_ip,
        resolver=config.resolver,
        sample_count=config.sample_count,
        sample_delay_seconds=config.sample_delay_seconds,
    )


def write_attack_success(path: str | Path, payload: dict[str, object]) -> None:
    Path(path).write_text(json.dumps(payload, indent=2) + "\n")
