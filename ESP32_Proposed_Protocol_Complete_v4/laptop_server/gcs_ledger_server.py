#!/usr/bin/env python3
"""Laboratory root ledger and untrusted LMS-path repository.

This service deliberately separates compact credential-root records from
per-index authentication paths. It uses an HMAC only to authenticate the lab
transport. It is not a production blockchain implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import signal
import socket
import sqlite3
import struct
import time
from pathlib import Path
from typing import Optional, Tuple

MAGIC = b"GCS2"
TAG_BYTES = 32
ID_BYTES = 32
ROOT_BYTES = 32
IDENTIFIER_BYTES = 16
PATH_BYTES = 320

OP_ENROLL_ROOT = 1
OP_ENROLL_PATH = 2
OP_GET_ROOT = 3
OP_GET_PATH = 4
OP_ROOT_RECORD = 5
OP_PATH_RECORD = 6
OP_ACK = 7
OP_NOT_FOUND = 8

ROOT_RECORD_BYTES = 140
PATH_RECORD_BYTES = 400
GET_ROOT_BYTES = 108
GET_PATH_BYTES = 112
ACK_BYTES = 84

LAB_KEY = bytes(
    [
        0x61, 0x94, 0x0D, 0x2F, 0x73, 0xE1, 0x48, 0xAC,
        0xB5, 0x39, 0x8C, 0x14, 0xD0, 0x6E, 0x2A, 0xF7,
        0x83, 0x45, 0x1B, 0xC9, 0x56, 0xAA, 0x30, 0x7D,
        0x1E, 0x68, 0xF2, 0x04, 0x9B, 0xCD, 0x77, 0x35,
    ]
)


def pack_u32(value: int) -> bytes:
    return struct.pack(">I", value)


def pack_u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def u32be(packet: bytes, offset: int) -> int:
    return struct.unpack_from(">I", packet, offset)[0]


def u64be(packet: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", packet, offset)[0]


def compute_tag(packet_without_tag: bytes) -> bytes:
    return hmac.new(LAB_KEY, packet_without_tag, hashlib.sha256).digest()


def verify_tag(packet: bytes) -> bool:
    if len(packet) < TAG_BYTES:
        return False
    return hmac.compare_digest(packet[-TAG_BYTES:], compute_tag(packet[:-TAG_BYTES]))


class Ledger:
    def __init__(self, db_path: Path, audit_path: Path) -> None:
        self.db_path = db_path
        self.audit_path = audit_path
        self.connection = sqlite3.connect(db_path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS credential_roots (
                device_id BLOB NOT NULL,
                version INTEGER NOT NULL,
                identifier BLOB NOT NULL,
                root BLOB NOT NULL,
                suite_id INTEGER NOT NULL,
                status INTEGER NOT NULL,
                expiry_unix INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY(device_id, version)
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS lms_paths (
                device_id BLOB NOT NULL,
                version INTEGER NOT NULL,
                q INTEGER NOT NULL,
                path BLOB NOT NULL,
                source_ip TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY(device_id, version, q)
            )
            """
        )
        self.connection.commit()
        self.previous_audit_hash = self._load_last_audit_hash()

    def close(self) -> None:
        self.connection.close()

    def _load_last_audit_hash(self) -> str:
        if not self.audit_path.exists():
            return "0" * 64
        last = ""
        with self.audit_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return "0" * 64
        try:
            return str(json.loads(last)["block_hash"])
        except (KeyError, json.JSONDecodeError):
            return "0" * 64

    def _append_audit(self, event: dict) -> None:
        body = dict(event)
        body["timestamp"] = time.time()
        body["previous_hash"] = self.previous_audit_hash
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        block_hash = hashlib.sha256(canonical).hexdigest()
        body["block_hash"] = block_hash
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True) + "\n")
        self.previous_audit_hash = block_hash

    def upsert_root(
        self,
        device_id: bytes,
        version: int,
        identifier: bytes,
        root: bytes,
        suite_id: int,
        status: int,
        expiry_unix: int,
        source_ip: str,
    ) -> bool:
        old = self.get_root(device_id, version)
        new_tuple = (identifier, root, suite_id, status, expiry_unix)
        unchanged = old == new_tuple
        if unchanged:
            return True

        self.connection.execute(
            """
            INSERT INTO credential_roots (
                device_id, version, identifier, root, suite_id,
                status, expiry_unix, source_ip, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, version) DO UPDATE SET
                identifier=excluded.identifier,
                root=excluded.root,
                suite_id=excluded.suite_id,
                status=excluded.status,
                expiry_unix=excluded.expiry_unix,
                source_ip=excluded.source_ip,
                updated_at=excluded.updated_at
            """,
            (
                device_id,
                version,
                identifier,
                root,
                suite_id,
                status,
                expiry_unix,
                source_ip,
                time.time(),
            ),
        )
        self.connection.commit()
        self._append_audit(
            {
                "event": "root",
                "device_id": device_id.hex(),
                "version": version,
                "identifier": identifier.hex(),
                "root": root.hex(),
                "suite_id": suite_id,
                "status": status,
                "expiry_unix": expiry_unix,
                "source_ip": source_ip,
            }
        )
        return False

    def upsert_path(
        self,
        device_id: bytes,
        version: int,
        q: int,
        path: bytes,
        source_ip: str,
    ) -> bool:
        old = self.get_path(device_id, version, q)
        unchanged = old == path
        if unchanged:
            return True
        self.connection.execute(
            """
            INSERT INTO lms_paths (
                device_id, version, q, path, source_ip, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, version, q) DO UPDATE SET
                path=excluded.path,
                source_ip=excluded.source_ip,
                updated_at=excluded.updated_at
            """,
            (device_id, version, q, path, source_ip, time.time()),
        )
        self.connection.commit()
        self._append_audit(
            {
                "event": "path",
                "device_id": device_id.hex(),
                "version": version,
                "q": q,
                "path_sha256": hashlib.sha256(path).hexdigest(),
                "source_ip": source_ip,
            }
        )
        return False

    def get_root(
        self, device_id: bytes, version: int
    ) -> Optional[Tuple[bytes, bytes, int, int, int]]:
        row = self.connection.execute(
            """
            SELECT identifier, root, suite_id, status, expiry_unix
            FROM credential_roots
            WHERE device_id=? AND version=?
            """,
            (device_id, version),
        ).fetchone()
        if row is None:
            return None
        identifier, root, suite_id, status, expiry_unix = row
        return bytes(identifier), bytes(root), int(suite_id), int(status), int(expiry_unix)

    def get_path(self, device_id: bytes, version: int, q: int) -> Optional[bytes]:
        row = self.connection.execute(
            """
            SELECT path FROM lms_paths
            WHERE device_id=? AND version=? AND q=?
            """,
            (device_id, version, q),
        ).fetchone()
        return None if row is None else bytes(row[0])

    def counts(self) -> Tuple[int, int]:
        roots = int(self.connection.execute("SELECT COUNT(*) FROM credential_roots").fetchone()[0])
        paths = int(self.connection.execute("SELECT COUNT(*) FROM lms_paths").fetchone()[0])
        return roots, paths


def parse_root_record(packet: bytes):
    if len(packet) != ROOT_RECORD_BYTES or packet[:4] != MAGIC or packet[4] != OP_ENROLL_ROOT:
        raise ValueError("invalid root-record format")
    if not verify_tag(packet):
        raise ValueError("invalid root-record HMAC")
    device_id = packet[8:40]
    version = u32be(packet, 40)
    identifier = packet[44:60]
    root = packet[60:92]
    suite_id = u32be(packet, 92)
    status = packet[96]
    expiry_unix = u64be(packet, 100)
    if status > 3:
        raise ValueError("invalid status")
    return device_id, version, identifier, root, suite_id, status, expiry_unix


def parse_path_record(packet: bytes):
    if len(packet) != PATH_RECORD_BYTES or packet[:4] != MAGIC or packet[4] != OP_ENROLL_PATH:
        raise ValueError("invalid path-record format")
    if not verify_tag(packet):
        raise ValueError("invalid path-record HMAC")
    device_id = packet[8:40]
    version = u32be(packet, 40)
    q = u32be(packet, 44)
    path = packet[48:368]
    if q >= 1024 or len(path) != PATH_BYTES:
        raise ValueError("invalid LMS path")
    return device_id, version, q, path


def parse_get_root(packet: bytes):
    if len(packet) != GET_ROOT_BYTES or packet[:4] != MAGIC or packet[4] != OP_GET_ROOT:
        raise ValueError("invalid GET_ROOT format")
    if not verify_tag(packet):
        raise ValueError("invalid GET_ROOT HMAC")
    return packet[8:40], packet[40:72], u32be(packet, 72)


def parse_get_path(packet: bytes):
    if len(packet) != GET_PATH_BYTES or packet[:4] != MAGIC or packet[4] != OP_GET_PATH:
        raise ValueError("invalid GET_PATH format")
    if not verify_tag(packet):
        raise ValueError("invalid GET_PATH HMAC")
    q = u32be(packet, 76)
    if q >= 1024:
        raise ValueError("q outside h=10 tree")
    return packet[8:40], packet[40:72], u32be(packet, 72), q


def build_ack(device_id: bytes, version: int, q: int, status: int = 0) -> bytes:
    packet = bytearray(ACK_BYTES)
    packet[:4] = MAGIC
    packet[4] = OP_ACK
    packet[8:40] = device_id
    packet[40:44] = pack_u32(version)
    packet[44:48] = pack_u32(q)
    packet[48] = status
    packet[-TAG_BYTES:] = compute_tag(packet[:-TAG_BYTES])
    return bytes(packet)


def build_not_found(target_id: bytes, version: int, q: int) -> bytes:
    packet = bytearray(ACK_BYTES)
    packet[:4] = MAGIC
    packet[4] = OP_NOT_FOUND
    packet[8:40] = target_id
    packet[40:44] = pack_u32(version)
    packet[44:48] = pack_u32(q)
    packet[48] = 1
    packet[-TAG_BYTES:] = compute_tag(packet[:-TAG_BYTES])
    return bytes(packet)


def build_root_response(
    device_id: bytes,
    version: int,
    identifier: bytes,
    root: bytes,
    suite_id: int,
    status: int,
    expiry_unix: int,
) -> bytes:
    packet = bytearray(ROOT_RECORD_BYTES)
    packet[:4] = MAGIC
    packet[4] = OP_ROOT_RECORD
    packet[8:40] = device_id
    packet[40:44] = pack_u32(version)
    packet[44:60] = identifier
    packet[60:92] = root
    packet[92:96] = pack_u32(suite_id)
    packet[96] = status
    packet[100:108] = pack_u64(expiry_unix)
    packet[-TAG_BYTES:] = compute_tag(packet[:-TAG_BYTES])
    return bytes(packet)


def build_path_response(device_id: bytes, version: int, q: int, path: bytes) -> bytes:
    packet = bytearray(PATH_RECORD_BYTES)
    packet[:4] = MAGIC
    packet[4] = OP_PATH_RECORD
    packet[8:40] = device_id
    packet[40:44] = pack_u32(version)
    packet[44:48] = pack_u32(q)
    packet[48:368] = path
    packet[-TAG_BYTES:] = compute_tag(packet[:-TAG_BYTES])
    return bytes(packet)


def send_reply(sock: socket.socket, payload: bytes, address, copies: int, spacing: float) -> None:
    for index in range(copies):
        sock.sendto(payload, address)
        if index + 1 < copies:
            time.sleep(spacing)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--db", type=Path, default=Path("gcs_ledger.sqlite3"))
    parser.add_argument("--audit", type=Path, default=Path("gcs_audit_chain.jsonl"))
    parser.add_argument("--reply-copies", type=int, default=1)
    parser.add_argument("--reply-spacing-ms", type=float, default=15.0)
    args = parser.parse_args()

    if args.reply_copies < 1:
        raise SystemExit("--reply-copies must be at least 1")

    ledger = Ledger(args.db, args.audit)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    sock.settimeout(1.0)
    running = True

    def stop_handler(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_handler)

    roots, paths = ledger.counts()
    print(f"GCS2 lab service listening on UDP {args.host}:{args.port}")
    print(f"Database: {args.db.resolve()}")
    print(f"Audit chain: {args.audit.resolve()}")
    print(f"Existing roots={roots}, paths={paths}, reply_copies={args.reply_copies}")

    try:
        while running:
            try:
                packet, address = sock.recvfrom(2048)
            except socket.timeout:
                continue

            source_ip, source_port = address
            if len(packet) < 5 or packet[:4] != MAGIC:
                continue

            try:
                op = packet[4]

                if op == OP_ENROLL_ROOT:
                    values = parse_root_record(packet)
                    unchanged = ledger.upsert_root(*values, source_ip)
                    device_id, version = values[0], values[1]
                    reply = build_ack(device_id, version, 0, 0)
                    send_reply(sock, reply, address, args.reply_copies, args.reply_spacing_ms / 1000.0)
                    print(f"ROOT device={device_id.hex()[:16]} version={version} unchanged={unchanged}")

                elif op == OP_ENROLL_PATH:
                    device_id, version, q, path = parse_path_record(packet)
                    unchanged = ledger.upsert_path(device_id, version, q, path, source_ip)
                    reply = build_ack(device_id, version, q, 0)
                    send_reply(sock, reply, address, args.reply_copies, args.reply_spacing_ms / 1000.0)
                    if q % 25 == 0:
                        print(f"PATH device={device_id.hex()[:16]} version={version} q={q} unchanged={unchanged}")

                elif op == OP_GET_ROOT:
                    requester, target, version = parse_get_root(packet)
                    record = ledger.get_root(target, version)
                    if record is None:
                        reply = build_not_found(target, version, 0)
                    else:
                        reply = build_root_response(target, version, *record)
                    send_reply(sock, reply, address, args.reply_copies, args.reply_spacing_ms / 1000.0)
                    print(f"GET_ROOT target={target.hex()[:16]} version={version} hit={record is not None}")

                elif op == OP_GET_PATH:
                    requester, target, version, q = parse_get_path(packet)
                    path = ledger.get_path(target, version, q)
                    if path is None:
                        reply = build_not_found(target, version, q)
                    else:
                        reply = build_path_response(target, version, q, path)
                    send_reply(sock, reply, address, args.reply_copies, args.reply_spacing_ms / 1000.0)
                    print(f"GET_PATH target={target.hex()[:16]} version={version} q={q} hit={path is not None}")

            except ValueError as error:
                print(f"Rejected packet from {source_ip}:{source_port}: {error}")

    finally:
        sock.close()
        ledger.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
