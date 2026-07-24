#!/usr/bin/env python3
"""Parse UAV_A Serial Monitor output from the revised ESP32 protocol.

Usage:
    python parse_serial_results.py uav_a_serial.txt

The parser writes one CSV row per successful session and reports the
statistics requested for the 500-session evaluation.
"""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from pathlib import Path
from typing import Iterable


HEADER = [
    "run",
    "qA",
    "qB",
    "path_mode",
    "A_protocol_us",
    "confirmed_e2e_us",
    "B_protocol_us",
    "A_crypto_us",
    "B_crypto_us",
    "A_puf_fe_us",
    "B_puf_fe_us",
    "A_repository_us",
    "B_repository_us",
    "direct_application_bytes",
    "direct_framed_bytes",
    "repository_application_bytes",
    "rssi_dbm",
    "free_heap",
    "min_free_heap",
]


def percentile(values: Iterable[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty values")
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def describe(label: str, values: list[float]) -> None:
    mean = statistics.fmean(values)
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    half_width = 1.96 * stdev / math.sqrt(len(values)) if len(values) > 1 else 0.0
    print(label)
    print(f"  n:       {len(values)}")
    print(f"  mean:    {mean:.3f}")
    print(f"  stdev:   {stdev:.3f}")
    print(f"  median:  {statistics.median(values):.3f}")
    print(f"  min:     {min(values):.3f}")
    print(f"  max:     {max(values):.3f}")
    print(f"  p95:     {percentile(values, 0.95):.3f}")
    print(f"  95% CI:  [{mean - half_width:.3f}, {mean + half_width:.3f}]")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("serial_log", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    output = args.output or args.serial_log.with_suffix(".csv")
    rows: list[list[int]] = []
    failed_lines = 0

    with args.serial_log.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if "Session " in line and " FAILED" in line:
                failed_lines += 1
            if not line.startswith("CSV,"):
                continue

            parts = line.split(",")
            if len(parts) != len(HEADER) + 1:
                print(
                    f"Ignored malformed CSV line with {len(parts) - 1} fields "
                    f"instead of {len(HEADER)}: {line}"
                )
                continue

            try:
                rows.append([int(value) for value in parts[1:]])
            except ValueError:
                print(f"Ignored non-integer CSV line: {line}")

    if not rows:
        raise SystemExit("No successful-session CSV lines were found.")

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        writer.writerows(rows)

    modes = {row[3] for row in rows}
    if len(modes) != 1:
        print(f"WARNING: log contains multiple path modes: {sorted(modes)}")
    mode_name = {1: "repository-assisted", 2: "signer-carried"}.get(
        rows[0][3], f"unknown-{rows[0][3]}"
    )

    confirmed = [row[5] / 1000.0 for row in rows]
    a_protocol = [row[4] / 1000.0 for row in rows]
    b_protocol = [row[6] / 1000.0 for row in rows]
    combined_crypto = [(row[7] + row[8]) / 1000.0 for row in rows]
    combined_puf_fe = [(row[9] + row[10]) / 1000.0 for row in rows]
    combined_repository = [(row[11] + row[12]) / 1000.0 for row in rows]
    rssi = [float(row[16]) for row in rows]

    print(f"Wrote {len(rows)} successful rows to {output}")
    print(f"Path mode: {mode_name}")
    print(f"Failure lines observed: {failed_lines}")
    print(f"Observed success fraction: {len(rows)}/{len(rows) + failed_lines}")
    print()
    describe("Confirmed end-to-end including measurement ACK, ms", confirmed)
    print()
    describe("Initiator protocol time through M4 send, ms", a_protocol)
    print()
    describe("Responder protocol time through M4 acceptance, ms", b_protocol)
    print()
    describe("Combined local cryptographic time, ms", combined_crypto)
    print()
    describe("Combined PUF/FE-hook time, ms", combined_puf_fe)
    print()
    describe("Combined runtime repository time, ms", combined_repository)
    print()
    describe("RSSI, dBm", rssi)
    print()
    print(f"Direct application bytes: {sorted({row[13] for row in rows})}")
    print(f"Repository application bytes: {sorted({row[15] for row in rows})}")
    print(f"Minimum observed free heap: {min(row[17] for row in rows)} bytes")
    print(f"Minimum reported historical heap: {min(row[18] for row in rows)} bytes")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
