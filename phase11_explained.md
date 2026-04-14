# Phase 11 Writeup — Project Report

This document is the Phase 11 deliverable from the implementation plan: the actual high-level project writeup. Unlike the earlier `phaseX_explained.md` files, this one is not a line-by-line code walkthrough. It is the report-style narrative that explains the problem, design, implementation, evaluation approach, and limitations of the repository as a whole.

Where possible, the claims below are grounded in artifacts that exist in this repository today. When a claim depends on a full live Docker run that was not executed in this session, that is stated explicitly rather than implied.

---

## 1. Introduction / Problem Statement

DNS cache poisoning remains a useful teaching case for network defense because it sits at the intersection of protocol design, resolver behavior, and practical attack timing. A recursive resolver accepts queries from local clients, performs upstream lookups on their behalf, and caches the resulting answers for future requests. If an attacker can cause the resolver to cache forged data, later clients may be redirected to malicious infrastructure without having to compromise the clients directly.

The classic Kaminsky attack demonstrated that a resolver can be pressured into many fresh upstream lookups and then flooded with spoofed responses that guess the correct transaction parameters. Modern resolvers reduce that risk with random source ports, transaction ID entropy, DNSSEC validation, glue hardening, and other defenses. Even so, attack-attempt visibility still matters. Operators benefit from knowing when a poisoning attempt is being staged, when suspicious authority or additional-section data appears, and when the local resolver diverges from trusted external answers.

This project implements a defense-in-depth detector around that idea. Instead of trying to replace resolver hardening, it monitors resolver-side DNS activity, raises alerts on suspicious patterns, and optionally verifies suspicious domains against trusted public resolvers. The result is a practical research and demonstration system that can show both attack attempts and, under a deliberately weakened resolver configuration, successful poisoning outcomes.

---

## 2. Background

### Recursive resolution and caching

When a client asks a recursive resolver for a name such as `www.example.com`, the resolver may need to contact upstream DNS servers to answer it. If the answer is not cached locally, the resolver performs iterative or recursive lookups, receives a response, and stores the result for its time-to-live (TTL). Subsequent clients benefit from the cached answer and see lower latency.

This distinction between cache hit and cache miss is central to cache poisoning. A cache hit does not create new upstream exposure. A cache miss does.

### The Kaminsky attack

A Kaminsky-style attack works by forcing the resolver to issue many upstream lookups for random subdomains under the same parent domain, for example:

- `a1.example.com`
- `a2.example.com`
- `a3.example.com`

Each fresh name is likely to miss the cache, so the resolver sends a new upstream query. The attacker then floods the resolver with forged responses that pretend to come from the authoritative server and guess the resolver's transaction parameters. If one forged response arrives first with the correct parameters, the resolver may accept it.

The dangerous version of the attack does not merely spoof a single A record. It tries to poison delegation-related data, such as forged `NS` records and glue, so later lookups for the entire zone can be redirected.

### Bailiwick

The bailiwick concept is a trust-boundary rule for DNS referrals and related records. In simplified terms, a resolver should be cautious about caching authority and additional-section data that is outside the zone context of the response being processed. A response about `example.com` should not be a vehicle for injecting unrelated data for names that have no business being trusted in that context.

This project implements a simplified bailiwick check suitable for a class or research prototype: authority and additional records are flagged when their owner names, or the domain-like targets embedded in relevant RDATA, fall outside the expected zone derived from the query name.

### 0x20 encoding and resolver hardening

Resolvers often increase spoofing resistance with several entropy sources:

- randomized transaction IDs
- randomized source ports
- optional 0x20 case randomization in query names
- glue hardening
- DNSSEC validation

These features do not mean attacks cease to exist as research problems. They mean the attack becomes harder to win. A detector can still be useful because it can surface precursor behavior and failed attempts even when the resolver ultimately resists poisoning.

### DNSSEC

DNSSEC adds signatures and a chain of trust to DNS data. A validating resolver can reject forged answers that fail signature validation. In practice, DNSSEC substantially strengthens integrity, but it does not eliminate the value of passive detection:

- not every zone is signed
- not every environment validates correctly
- internal/private DNS often lacks DNSSEC
- failed attacks are still worth detecting and logging

---

## 3. Threat Model

### In scope

This project focuses on attacker behavior that targets the resolver's upstream lookup path, especially:

- unsolicited spoofed responses
- duplicate competing responses for the same query tuple
- bursts of unique random subdomain queries under one parent domain
- out-of-bailiwick authority or additional data in resolver responses
- resolver-answer divergence from trusted external resolvers

The attacker is assumed to have the ability to trigger queries and to send spoofed packets that race legitimate upstream responses. In the Docker lab, the attacker container is granted raw-socket capabilities to make those experiments possible.

### Out of scope

The detector does not attempt to handle:

- endpoint compromise on the client host
- encrypted DNS abuse beyond the verification lookups the detector itself makes
- authoritative server compromise as a separate incident class
- full RFC-accurate bailiwick validation
- every resolver implementation or every DNS edge case

The detector is also not designed as a drop-in production IDS for the public Internet. It is a focused prototype aimed at cache-poisoning detection logic and attack-attempt visibility.

### Assumptions

The design assumes:

- Unbound is the recursive resolver being monitored
- dnstap is available and used for structured event ingestion
- the detector can observe resolver-facing query and response events
- the detector can reach trusted public DoH endpoints when active verification is enabled
- a weak resolver configuration may be used for demonstration, while a hardened one is used for comparison

---

## 4. System Design

### Architecture overview

The system is split into four containers:

- `resolver`: Unbound, in weak or hardened mode
- `detector`: dnstap ingestion, heuristics, verification, and JSON logging
- `client`: realistic benign traffic generator using `dig`
- `attacker`: Scapy-based attack scripts for Kaminsky flooding and bailiwick injection

The main runtime pipeline is:

1. Unbound emits dnstap events over a Unix socket.
2. The detector ingests frame streams, decodes protobuf payloads, and parses DNS wire data into `DNSEvent` objects.
3. Each event is passed through passive heuristics.
4. When a heuristic fires, the detector optionally performs active verification for the affected domain.
5. Alerts and periodic summaries are emitted as JSON lines.

### Internal event model

The detector normalizes traffic into a `DNSEvent` dataclass containing:

- timestamp
- event type (`query` or `response`)
- message type (`resolver_query`, `resolver_response`, `client_query`, `client_response`)
- query name and type
- transaction ID
- source and destination IPs and ports
- response code
- answer, authority, and additional sections

That shared model keeps parsing concerns separate from detection logic.

### Heuristic 1: query-response matching

The first heuristic tracks pending resolver queries by a tuple of:

- query name
- query type
- transaction ID
- source port

It raises:

- `unsolicited_response` when a resolver response arrives with no matching pending query
- `duplicate_response` when a second response arrives for the same pending query before the duplicate grace window expires

This heuristic captures suspicious upstream response behavior directly. It is especially useful for spoofing races and malformed response patterns.

### Heuristic 2: Kaminsky precursor detection

The second heuristic tracks unique query names under each parent domain within a sliding time window. If the count of distinct subdomains under one parent crosses a threshold, it emits a `kaminsky_precursor` alert.

This heuristic does not require a successful poisoning outcome. It focuses on the setup pattern that gives a Kaminsky attacker repeated chances to race spoofed responses.

### Heuristic 3: simplified bailiwick enforcement

The third heuristic inspects `resolver_response` events and derives an expected bailiwick zone from the query name. It scans authority and additional records and flags:

- out-of-zone owner names
- domain-like targets inside relevant RDATA that point outside the expected zone

This simplified check is intentionally conservative and educational rather than RFC-complete, but it is effective at catching the class of suspicious delegation and glue injection attempts the project cares about.

### Active verification

When a passive alert fires, the detector can verify the affected domain by comparing:

- the local Unbound answer
- Cloudflare DoH answer set
- Google DoH answer set

The verifier treats the union of trusted resolver answers as the comparison baseline and classifies results as:

- `MATCH`
- `CONFIRMED`
- `VERIFICATION_FAILED`

Results are cached for a short cooldown window so repeated alerts for the same domain do not trigger repeated network lookups.

### Logging and observability

All alerts are emitted as one JSON object per line. The detector also emits periodic summary objects containing:

- events processed
- pending-query count
- alerts fired
- verification result counts

This makes the detector suitable for downstream parsing with shell tools, `jq`, or the Phase 10 evaluation scripts.

---

## 5. Attack Feasibility and Dual-Configuration Strategy

### Why two resolver configurations are necessary

One of the most important design choices in this repository is the use of two Unbound configurations:

- a weak configuration for demonstration
- a hardened configuration for comparison

This is not a gimmick. It is what allows the project to show both attack feasibility and the continuing value of detection.

### Weak configuration

The weak resolver deliberately reduces protection by fixing or constraining some entropy and by disabling validation-related protections. In this mode, it becomes much easier to demonstrate:

- Kaminsky-style spoofing races
- injected delegation or glue attempts
- the difference between an attack attempt and a successful poisoned cache

### Hardened configuration

The hardened resolver keeps modern protections in place. In this mode, the same attack traffic may still be observable, but it is expected to be far harder to turn into an actual poisoned cache.

### What the two configs prove together

The weak configuration shows the detector can operate in an environment where attacks are easier to demonstrate and, potentially, succeed.

The hardened configuration shows:

- the same passive heuristics can still see suspicious traffic patterns
- verification can distinguish an attack attempt from a successful poisoning outcome
- resolver hardening and passive detection complement rather than replace one another

This dual-configuration strategy is therefore central to the project's argument. The project is strongest when framed as a detector around resolver hardening, not as a substitute for resolver hardening.

---

## 6. Implementation

### Technology stack

The project uses:

- Docker Compose for environment orchestration
- Unbound as the recursive resolver
- Python 3.11 for detector, attacker, client, and support tooling
- `dnstap-pb`, `protobuf`, and `fstrm` for dnstap ingestion
- `dnspython` for DNS parsing and local resolution
- `httpx` for async DoH verification
- Scapy for packet crafting and sniffing

### Key implementation decisions

#### Dnstap as the primary ingestion path

Although the original plan allowed a text-log fallback, the repository now treats dnstap as the real data path. This keeps the detector closer to resolver-internal structure and avoids the ambiguities of text-log parsing.

#### Async detector pipeline

The detector uses `asyncio` end to end. That keeps the ingestion loop, verification lookups, and periodic summary task in a single coherent runtime model.

#### Heuristic modularity

Each heuristic lives in its own module under `detector/src/heuristics/`. That keeps state local and makes testing straightforward.

#### JSON-first output

Instead of mixing human-readable logs with ad hoc prints, the detector emits structured JSON. This made the Phase 10 evaluation harness much easier to build and keeps later analysis reproducible.

### Supporting tooling

The later phases add supporting infrastructure around the detector:

- attacker scripts for Kaminsky-style flooding and bailiwick injection
- a normal traffic generator for baseline behavior
- a log parser for extracting evaluation summaries
- an orchestration shell script for running scenario batches

By Phase 10, the repository has evolved from a parser plus heuristics into a complete experimental environment.

---

## 7. Evaluation

### Evaluation goals

The evaluation design aims to answer four high-level questions:

1. Does the detector remain quiet during normal traffic?
2. Does it detect Kaminsky-style precursor and spoofing behavior?
3. Does it detect bailiwick-oriented injection attempts?
4. Does active verification distinguish successful poisoning from failed attempts?

### Scenario design

The Phase 10 harness defines these scenarios:

- normal traffic against weak config
- normal traffic against hardened config
- Kaminsky flood against weak config
- Kaminsky flood against hardened config
- bailiwick injection against weak config
- bailiwick injection against hardened config

For each scenario, the harness can record:

- passive alert types observed
- verification status
- whether post-attack resolution appears poisoned
- first-alert latency

### What has been validated in this repository

Within this session and the local repository, the following have been validated:

- Python modules compile successfully with `py_compile`
- heuristic-specific unit and component tests exist for Phases 3 through 10
- the detector log parser is tested locally
- the attacker packet-shape test suite exists and skips cleanly when host-side `scapy` is unavailable
- Docker Compose access is available, and the repository includes an executable scenario harness

### What has not been fully measured in this session

A full long-running end-to-end evaluation batch was not executed in this session, so this report does **not** claim measured values for:

- true positive rate under repeated live attack runs
- false positive rate over a multi-minute baseline run
- attack success rate differences between weak and hardened configs
- measured end-to-end detection latency across repeated trials

That distinction matters. The repository contains the tooling required to generate those results, but the numeric results themselves should only be reported after running the Phase 10 harness in a live Docker environment.

### Current evidence-backed interpretation

Based on the implemented logic and local validation, the project supports the following claims with confidence:

- the detector can ingest structured resolver events from dnstap
- the detector can identify suspicious query/response patterns, precursor bursts, and simplified bailiwick violations
- the verifier can compare local answers with trusted public resolvers and annotate alerts
- the logging format is structured enough for automated post-processing
- the evaluation workflow is scripted rather than manual

The stronger empirical claims, such as exact latency and attack success under each resolver configuration, remain evaluation outputs to be collected rather than assumptions to be embedded in the report.

### Results table template

When the evaluation harness is run to completion, the project is designed to produce a table in the following form:

| Scenario | Config | Passive Alerts | Verification | Cache Poisoned | Detection Latency |
|---|---|---|---|---|---|
| Normal traffic | Weak | 0 | N/A | No | N/A |
| Normal traffic | Hardened | 0 | N/A | No | N/A |
| Kaminsky flood | Weak | precursor + q/r match | pending live run | pending live run | pending live run |
| Kaminsky flood | Hardened | precursor + q/r match | pending live run | pending live run | pending live run |
| Bailiwick injection | Weak | bailiwick violation | pending live run | pending live run | pending live run |
| Bailiwick injection | Hardened | bailiwick violation | pending live run | pending live run | pending live run |

This table is intentionally honest: it reflects the structure the harness is built to populate, while avoiding invented measurements.

---

## 8. Limitations and Future Work

### Current limitations

The project has several important limitations.

#### Simplified bailiwick logic

Real bailiwick handling in recursive resolvers is more nuanced than the simplified zone check used here. Some legitimate referrals can involve names outside the naive zone suffix rule, so this heuristic should be understood as an educational poisoning-attempt detector, not a full resolver policy implementation.

#### Limited attack coverage

The detector targets a focused slice of poisoning-related behavior. It does not attempt to cover all DNS abuse, all resolver bugs, or all authoritative-side compromises.

#### Dependence on resolver visibility

The system assumes visibility into resolver-side traffic via dnstap. It is not designed for environments where only client-side DNS activity is available.

#### Verification trust model

The active verification step assumes public resolvers such as Cloudflare and Google are acceptable comparison points. That is reasonable for a class project, but it is still a trust choice with operational implications.

#### Incomplete empirical results in this document

The repository includes the Phase 10 evaluation harness, but this document does not yet include measured multi-run scenario results because those were not executed in this session.

### Future work

Several improvements would make the project stronger:

- run the full evaluation matrix multiple times and record measured latency and consistency
- make bailiwick checking more RFC-aware
- add persistent storage or export to a SIEM-friendly destination
- expand verification to additional trusted resolvers or DNSSEC-aware validation paths
- add explicit handling for negative caching and NXDOMAIN-focused attack patterns
- support richer domain parsing, such as public-suffix-aware parent extraction
- build visualization around the Phase 10 results and periodic summaries

---

## 9. Conclusion

This project demonstrates a practical DNS cache-poisoning detector built around resolver-side visibility rather than resolver hardening alone. It ingests dnstap events, applies three complementary passive heuristics, optionally verifies suspicious domains against trusted external resolvers, and emits structured logs suitable for evaluation and later analysis.

Its strongest contribution is the combination of:

- passive attack-attempt detection
- active confirmation logic
- dual weak/hardened resolver configurations
- reproducible Docker-based tooling around both benign traffic and attack simulation

Even in a world where modern resolvers and DNSSEC reduce the odds of classic poisoning success, there is still value in seeing the attempt. This repository is useful precisely because it treats poisoning as both a prevention problem and an observability problem.

---

## Appendix: Repository Artifacts Supporting This Writeup

The following repository artifacts correspond directly to the sections above:

- `detector/src/ingest_dnstap.py` — dnstap ingestion
- `detector/src/models.py` — internal event model
- `detector/src/heuristics/query_response.py` — query-response matching
- `detector/src/heuristics/kaminsky_precursor.py` — random-subdomain precursor detection
- `detector/src/heuristics/bailiwick.py` — simplified bailiwick enforcement
- `detector/src/verification.py` — active verification
- `detector/src/logger.py` — structured alert and summary logging
- `attacker/kaminsky_flood.py` — Kaminsky-style traffic generator
- `attacker/bailiwick_inject.py` — bailiwick injection simulator
- `client/traffic_generator.py` — benign baseline traffic generator
- `scripts/run_evaluation.sh` — scenario orchestration
- `scripts/parse_detector_log.py` — detector log summarization

The earlier phase documents remain useful companion references:

- `phase3_explained.md`
- `phase4_explained.md`
- `phase5_explained.md`
- `phase6_explained.md`
- `phase7_explained.md`
- `phase8_explained.md`
- `phase9_explained.md`
- `phase10_explained.md`
