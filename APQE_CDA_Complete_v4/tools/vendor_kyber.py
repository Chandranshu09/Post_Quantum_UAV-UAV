#!/usr/bin/env python3
"""Vendor the official CRYSTALS-Kyber reference CPA-PKE source.

The APQE paper uses Kyber.CPAPKE rather than ML-KEM. This script copies only
files required by the Kyber-512 IND-CPA layer from the official repository.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

COMMIT = "441c0519a07e8b86c8d079954a6b10bd31d29efc"
FILES = [
    "cbd.c", "cbd.h",
    "fips202.c", "fips202.h",
    "indcpa.c", "indcpa.h",
    "ntt.c", "ntt.h",
    "params.h",
    "poly.c", "poly.h",
    "polyvec.c", "polyvec.h",
    "reduce.c", "reduce.h",
    "symmetric-shake.c", "symmetric.h",
]


def run(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def write_deterministic_random_adapter(target: Path) -> None:
    """Provide randombytes() from the emulated SRAM-PUF-derived seed."""
    (target / "randombytes.h").write_text(
        r'''#ifndef APQE_RANDOMBYTES_H
#define APQE_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void apqe_randombytes_set_seed(const uint8_t seed[32]);
void randombytes(uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif
''',
        encoding="utf-8",
    )

    (target / "randombytes.c").write_text(
        r'''#include "randombytes.h"

#include <string.h>

#include "fips202.h"

static uint8_t apqe_seed[32];
static uint32_t apqe_counter = 0;

void apqe_randombytes_set_seed(const uint8_t seed[32])
{
    memcpy(apqe_seed, seed, 32);
    apqe_counter = 0;
}

void randombytes(uint8_t *out, size_t outlen)
{
    while (outlen > 0) {
        uint8_t input[36];
        uint8_t block[32];
        memcpy(input, apqe_seed, 32);
        input[32] = (uint8_t)(apqe_counter >> 24);
        input[33] = (uint8_t)(apqe_counter >> 16);
        input[34] = (uint8_t)(apqe_counter >> 8);
        input[35] = (uint8_t)apqe_counter;
        shake256(block, sizeof(block), input, sizeof(input));
        ++apqe_counter;

        size_t take = outlen < sizeof(block) ? outlen : sizeof(block);
        memcpy(out, block, take);
        out += take;
        outlen -= take;
    }
}
''',
        encoding="utf-8",
    )


def main() -> None:
    package_root = Path(__file__).resolve().parents[1]
    target = package_root / "Arduino/libraries/ApqeCdaProtocol/src/vendor/kyber_ref"
    target.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="apqe-kyber-") as temporary:
        repository = Path(temporary) / "kyber"
        run("git", "clone", "https://github.com/pq-crystals/kyber.git", str(repository))
        run("git", "checkout", COMMIT, cwd=repository)

        for filename in FILES:
            source = repository / "ref" / filename
            if not source.exists():
                raise FileNotFoundError(f"Required upstream file not found: {source}")
            shutil.copy2(source, target / filename)

        shutil.copy2(repository / "LICENSE", target / "UPSTREAM_LICENSE")

    params_path = target / "params.h"
    params = params_path.read_text(encoding="utf-8")
    if "#define KYBER_K 3" in params:
        params = params.replace("#define KYBER_K 3", "#define KYBER_K 2", 1)
    elif "#define KYBER_K 2" not in params:
        raise RuntimeError("Could not set Kyber-512 in params.h")
    params_path.write_text(params, encoding="utf-8")

    write_deterministic_random_adapter(target)
    (target / "VENDORED_COMMIT.txt").write_text(COMMIT + "\n", encoding="utf-8")
    placeholder = target / "README_VENDOR_REQUIRED.txt"
    if placeholder.exists():
        placeholder.unlink()

    print(f"Kyber reference CPA source installed in: {target}")
    print(f"Pinned upstream commit: {COMMIT}")


if __name__ == "__main__":
    main()
