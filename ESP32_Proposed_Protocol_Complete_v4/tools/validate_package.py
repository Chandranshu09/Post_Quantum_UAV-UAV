#!/usr/bin/env python3
"""Static and Python-level self-tests for the revised package."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "laptop_server" / "gcs_ledger_server.py"


def load_server():
    spec = importlib.util.spec_from_file_location("gcs_ledger_server", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load server module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_message_arithmetic() -> None:
    m0 = 86
    m1 = 102
    m2_base = 3022
    m3_base = 3058
    m4 = 66
    path = 320
    assert m0 + m1 + m2_base + m3_base + m4 == 6334
    assert m0 + m1 + (m2_base + path) + (m3_base + path) + m4 == 6974
    assert 112 + 400 + 112 + 400 == 1024
    assert 6334 + 1024 == 7358
    assert 6334 + 11 * 14 == 6488
    assert 6974 + 11 * 14 == 7128


def test_server_packets(server) -> None:
    device_id = b"A" * 32
    identifier = bytes(range(16))
    root = b"R" * 32
    path = bytes((i % 251 for i in range(320)))

    root_packet = server.build_root_response(
        device_id, 1, identifier, root, 0x00010001, 1, 0
    )
    path_packet = server.build_path_response(device_id, 1, 7, path)
    ack_packet = server.build_ack(device_id, 1, 7)
    not_found = server.build_not_found(device_id, 1, 7)

    assert len(root_packet) == server.ROOT_RECORD_BYTES == 140
    assert len(path_packet) == server.PATH_RECORD_BYTES == 400
    assert len(ack_packet) == server.ACK_BYTES == 84
    assert len(not_found) == server.ACK_BYTES == 84
    assert server.verify_tag(root_packet)
    assert server.verify_tag(path_packet)
    assert server.verify_tag(ack_packet)
    assert server.verify_tag(not_found)

    with tempfile.TemporaryDirectory() as directory:
        db = Path(directory) / "ledger.sqlite3"
        audit = Path(directory) / "audit.jsonl"
        ledger = server.Ledger(db, audit)
        try:
            assert not ledger.upsert_root(
                device_id, 1, identifier, root, 0x00010001, 1, 0, "127.0.0.1"
            )
            assert ledger.upsert_root(
                device_id, 1, identifier, root, 0x00010001, 1, 0, "127.0.0.1"
            )
            assert not ledger.upsert_path(device_id, 1, 7, path, "127.0.0.1")
            assert ledger.upsert_path(device_id, 1, 7, path, "127.0.0.1")
            assert ledger.get_root(device_id, 1) == (
                identifier,
                root,
                0x00010001,
                1,
                0,
            )
            assert ledger.get_path(device_id, 1, 7) == path
            assert ledger.counts() == (1, 1)
        finally:
            ledger.close()


def test_source_invariants() -> None:
    source = (
        ROOT
        / "Arduino"
        / "libraries"
        / "ProposedUavProtocol"
        / "src"
        / "ProposedUavProtocol.cpp"
    ).read_text(encoding="utf-8")
    constants = (
        ROOT
        / "Arduino"
        / "libraries"
        / "ProposedUavProtocol"
        / "src"
        / "ProtocolConstants.h"
    ).read_text(encoding="utf-8")

    required = [
        "DOMAIN_SID0",
        "putU16(input + offset, M0_BYTES)",
        "putU16(input + offset, M1_BYTES)",
        "DOMAIN_LMOTS_SIGN",
        "putU32(m_signInput + 4 + MU_A_BYTES, q)",
        "putU32(m_signInput + 4 + MU_B_BYTES, q)",
        "SESSION_KEY_MATERIAL_BYTES = 96",
        "confirmA",
        "confirmB",
        "PufFeProvider::reconstruct",
        "PathDeliveryMode::RepositoryAssisted",
        "PathDeliveryMode::SignerCarried",
    ]
    combined = source + "\n" + constants
    for needle in required:
        assert needle in combined, f"missing source invariant: {needle}"

    for sketch in (ROOT / "Arduino").glob("UAV_*/*.ino"):
        text = sketch.read_text(encoding="utf-8")
        assert "500" in text
        assert "hardcoded" in text.lower()
        assert "RESET_Q_COUNTER" in text


if __name__ == "__main__":
    server = load_server()
    test_message_arithmetic()
    test_server_packets(server)
    test_source_invariants()
    print("All package validation tests passed.")
