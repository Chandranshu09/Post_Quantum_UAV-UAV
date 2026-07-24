#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import time

KEY = bytes([
    0x7a,0x0c,0x9e,0x51,0x2b,0xd8,0x44,0xf0,
    0xa1,0x63,0x37,0x8d,0xe4,0x05,0xc9,0x72,
    0x19,0xb6,0x2f,0xaa,0x84,0x33,0xd1,0x5c,
    0x68,0xef,0x90,0x47,0x12,0xbc,0x5a,0x26,
])
MAGIC = 0xA952


def ping(port: int) -> None:
    request_id = int(time.time() * 1000) & 0xFFFFFFFF
    header = struct.pack(">HBBIHH", MAGIC, 1, 4, request_id, 0, 0)
    packet = header + hmac.new(KEY, header, hashlib.sha256).digest()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    started = time.perf_counter_ns()
    sock.sendto(packet, ("127.0.0.1", port))
    response, _ = sock.recvfrom(2048)
    wall_ms = (time.perf_counter_ns() - started) / 1e6
    if len(response) < 51:
        raise RuntimeError(f"short response on {port}: {len(response)}")
    magic, version, op, returned_id = struct.unpack(">HBBI", response[:8])
    status = response[8]
    fabric_us = struct.unpack(">Q", response[9:17])[0]
    payload_len = struct.unpack(">H", response[17:19])[0]
    authenticated = response[:19 + payload_len]
    tag = response[19 + payload_len:]
    if magic != MAGIC or version != 1 or op != 0x84 or returned_id != request_id:
        raise RuntimeError(f"invalid response header on port {port}")
    if not hmac.compare_digest(hmac.new(KEY, authenticated, hashlib.sha256).digest(), tag):
        raise RuntimeError(f"invalid response HMAC on port {port}")
    print(f"gateway {port}: status={status}, fabric_us={fabric_us}, wall_ms={wall_ms:.3f}")


for gateway_port in (5002, 5003):
    ping(gateway_port)
