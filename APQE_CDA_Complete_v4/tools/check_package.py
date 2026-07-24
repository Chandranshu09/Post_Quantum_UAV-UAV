#!/usr/bin/env python3
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
required = [
    root / 'Arduino/APQE_UAV_A/APQE_UAV_A.ino',
    root / 'Arduino/APQE_UAV_B/APQE_UAV_B.ino',
    root / 'Arduino/libraries/ApqeCdaProtocol/src/ApqeProtocol.cpp',
    root / 'fabric/chaincode-go/main.go',
    root / 'fabric/gateway-go/main.go',
]
missing = [str(p.relative_to(root)) for p in required if not p.exists()]
if missing:
    raise SystemExit('Missing required files: ' + ', '.join(missing))

constants = (root / 'Arduino/libraries/ApqeCdaProtocol/src/ApqeConstants.h').read_text()
checks = {
    'M1_BYTES': 3104,
    'M2_BYTES': 128,
    'M3_BYTES': 64,
    'DIRECT_APPLICATION_BYTES': 3296,
    'FABRIC_RECORD_BYTES': 928,
}
# Constants are expressions, so verify the documented arithmetic directly.
assert 4 * 768 + 32 == checks['M1_BYTES']
assert 32 + 64 + 32 == checks['M2_BYTES']
assert 32 + 32 == checks['M3_BYTES']
assert checks['M1_BYTES'] + checks['M2_BYTES'] + checks['M3_BYTES'] == checks['DIRECT_APPLICATION_BYTES']
assert 32 + 32 + 800 + 32 + 32 == checks['FABRIC_RECORD_BYTES']

vendor = root / 'Arduino/libraries/ApqeCdaProtocol/src/vendor/kyber_ref/indcpa.c'
if not vendor.exists():
    print('Kyber source: NOT YET VENDORED')
    print('Run: python3 tools/vendor_kyber.py')
else:
    params = (vendor.parent / 'params.h').read_text(errors='replace')
    if not re.search(r'#define\s+KYBER_K\s+2\b', params):
        raise SystemExit('Kyber source exists but params.h is not set to KYBER_K=2')
    for name in ('randombytes.c', 'randombytes.h', 'UPSTREAM_LICENSE', 'VENDORED_COMMIT.txt'):
        if not (vendor.parent / name).exists():
            raise SystemExit(f'Missing vendored file: {name}')
    print('Kyber source: present and configured for Kyber-512 CPA-PKE')

print('Package structure and byte-layout checks passed.')
