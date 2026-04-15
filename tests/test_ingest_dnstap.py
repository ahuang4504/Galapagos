import ipaddress
import struct
import sys
from datetime import datetime

import dns.message
import dns.rrset

sys.path.insert(0, "detector/src")

from ingest_dnstap import (
    DNSTAP_CONTENT_TYPE,
    _dnstap_payload_to_event,
    _pack_control_frame,
    _parse_control_frame,
)


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            return bytes(out)


def encode_field_varint(number: int, value: int) -> bytes:
    return encode_varint((number << 3) | 0) + encode_varint(value)


def encode_field_fixed32(number: int, value: int) -> bytes:
    return encode_varint((number << 3) | 5) + struct.pack("<I", value)


def encode_field_bytes(number: int, value: bytes) -> bytes:
    return encode_varint((number << 3) | 2) + encode_varint(len(value)) + value


def build_dnstap_payload(message_type: int, dns_wire: bytes, *, tx_time: datetime, response: bool) -> bytes:
    message = bytearray()
    message.extend(encode_field_varint(1, message_type))
    message.extend(encode_field_bytes(4, ipaddress.ip_address("172.28.0.10").packed))
    message.extend(encode_field_bytes(5, ipaddress.ip_address("198.41.0.4").packed))
    message.extend(encode_field_varint(6, 5300))
    message.extend(encode_field_varint(7, 53))
    if response:
        message.extend(encode_field_varint(12, int(tx_time.timestamp())))
        message.extend(encode_field_fixed32(13, tx_time.microsecond * 1000))
        message.extend(encode_field_bytes(14, dns_wire))
    else:
        message.extend(encode_field_varint(8, int(tx_time.timestamp())))
        message.extend(encode_field_fixed32(9, tx_time.microsecond * 1000))
        message.extend(encode_field_bytes(10, dns_wire))

    top = bytearray()
    top.extend(encode_field_varint(15, 1))
    top.extend(encode_field_bytes(14, bytes(message)))
    return bytes(top)


def test_control_frame_round_trip() -> None:
    frame = _pack_control_frame(0x04, DNSTAP_CONTENT_TYPE)
    assert frame[:4] == b"\x00\x00\x00\x00"
    payload_length = struct.unpack("!I", frame[4:8])[0]
    control_type, fields = _parse_control_frame(frame[8 : 8 + payload_length])
    assert control_type == 0x04
    assert fields[1] == [DNSTAP_CONTENT_TYPE]


def test_dnstap_payload_to_event_maps_resolver_query() -> None:
    query = dns.message.make_query("rand1.example.com", "A")
    payload = build_dnstap_payload(
        3,
        query.to_wire(),
        tx_time=datetime(2026, 4, 14, 12, 0, 0),
        response=False,
    )

    event = _dnstap_payload_to_event(payload)

    assert event is not None
    assert event.sensor == "dnstap"
    assert event.event_type == "query"
    assert event.message_type == "resolver_query"
    assert event.query_name == "rand1.example.com"
    assert event.query_type == "A"
    assert event.source_ip == "172.28.0.10"
    assert event.dest_ip == "198.41.0.4"
    assert event.source_port == 5300
    assert event.dest_port == 53


def test_dnstap_payload_to_event_maps_resolver_response() -> None:
    query = dns.message.make_query("rand1.example.com", "A")
    response = dns.message.make_response(query)
    response.answer.append(
        dns.rrset.from_text("rand1.example.com.", 300, "IN", "A", "6.6.6.6")
    )
    response.authority.append(
        dns.rrset.from_text("example.com.", 300, "IN", "NS", "ns1.attacker.net.")
    )
    response.additional.append(
        dns.rrset.from_text("ns1.attacker.net.", 300, "IN", "A", "6.6.6.6")
    )
    payload = build_dnstap_payload(
        4,
        response.to_wire(),
        tx_time=datetime(2026, 4, 14, 12, 0, 1),
        response=True,
    )

    event = _dnstap_payload_to_event(payload)

    assert event is not None
    assert event.sensor == "dnstap"
    assert event.event_type == "response"
    assert event.message_type == "resolver_response"
    assert event.query_name == "rand1.example.com"
    assert event.query_type == "A"
    assert event.source_ip == "198.41.0.4"
    assert event.dest_ip == "172.28.0.10"
    assert event.response_code == "NOERROR"
    assert event.answers == [("rand1.example.com", "A", 300, "6.6.6.6")]
    assert event.authority == [("example.com", "NS", 300, "ns1.attacker.net")]
    assert event.additional == [("ns1.attacker.net", "A", 300, "6.6.6.6")]
