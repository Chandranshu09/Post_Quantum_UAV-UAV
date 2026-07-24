Run this once from the package root before opening Arduino IDE:

    python3 tools/vendor_kyber.py

The script copies the official CRYSTALS-Kyber reference IND-CPA source at the
pinned commit recorded in tools/vendor_kyber.py. The source is not duplicated
in this generated archive to keep upstream provenance explicit.
