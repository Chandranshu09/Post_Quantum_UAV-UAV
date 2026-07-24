#!/usr/bin/env python3
from pathlib import Path

for name in (
    "gcs_ledger.sqlite3",
    "gcs_ledger.sqlite3-wal",
    "gcs_ledger.sqlite3-shm",
    "gcs_audit_chain.jsonl",
):
    path = Path(name)
    if path.exists():
        path.unlink()
        print(f"Deleted {path}")
