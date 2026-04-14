from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class DNSEvent:
    timestamp: datetime
    event_type: str       # "query" or "response"
    message_type: str     # "client_query", "client_response", "resolver_query", "resolver_response"
    query_name: str
    query_type: str
    transaction_id: int   # 16-bit TXID — used to match queries to responses
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    response_code: Optional[str] = None  # only set on responses
    answers: list = field(default_factory=list)   # [(name, rdtype, ttl, rdata), ...]
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)
    sensor: str = "wire"
