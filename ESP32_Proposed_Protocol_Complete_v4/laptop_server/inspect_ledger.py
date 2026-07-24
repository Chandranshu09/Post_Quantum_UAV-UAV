#!/usr/bin/env python3
from pathlib import Path
import sqlite3

DB = Path("gcs_ledger.sqlite3")
if not DB.exists():
    raise SystemExit("No gcs_ledger.sqlite3 file found.")

connection = sqlite3.connect(DB)
print("Credential roots:")
for row in connection.execute(
    "SELECT hex(device_id), version, hex(identifier), hex(root), suite_id, status, expiry_unix FROM credential_roots ORDER BY device_id, version"
):
    print(row)

print("\nPath counts:")
for row in connection.execute(
    "SELECT hex(device_id), version, COUNT(*), MIN(q), MAX(q) FROM lms_paths GROUP BY device_id, version ORDER BY device_id, version"
):
    print(row)

connection.close()
