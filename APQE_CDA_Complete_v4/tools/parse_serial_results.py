#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path

COLUMNS = [
    "session", "slot", "a_protocol_us", "confirmed_us", "b_protocol_us",
    "a_crypto_us", "b_crypto_us", "direct_bytes", "framed_bytes",
    "a_gateway_bytes", "b_gateway_bytes", "rssi", "free_heap", "min_heap",
]


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 parse_serial_results.py serial_output.txt")
    rows = []
    for line in Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("CSV,"):
            continue
        values = [int(value) for value in line.split(",")[1:]]
        if len(values) != len(COLUMNS):
            raise ValueError(f"Unexpected CSV field count: {line}")
        rows.append(dict(zip(COLUMNS, values)))
    if not rows:
        raise SystemExit("No APQE CSV rows found")

    output = Path(sys.argv[1]).with_suffix(".csv")
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"sessions: {len(rows)}")
    for field in ("a_protocol_us", "confirmed_us", "b_protocol_us", "a_crypto_us", "b_crypto_us"):
        data = [row[field] / 1000 for row in rows]
        print(f"{field}: mean={statistics.mean(data):.3f} ms, min={min(data):.3f}, max={max(data):.3f}")
    for field in ("direct_bytes", "framed_bytes", "a_gateway_bytes", "b_gateway_bytes"):
        unique = sorted({row[field] for row in rows})
        print(f"{field}: {unique}")
    print(f"CSV written to: {output}")


if __name__ == "__main__":
    main()
