# Manuscript changes required to match v4

The earlier manuscript text described one PUF response and helper string per
`(version, q)`. The selected implementation now follows conventional LMS key
generation more closely:

1. The physical APUF and fuzzy extractor reconstruct one stable device-root
   value.
2. HKDF derives one LMS master seed per `(device, version, identifier)`.
3. RFC 8554 indexing by `I`, `q`, and chain index generates all LM-OTS private
   values under that tree.
4. The 1024 corresponding public values form the height-10 LMS tree.

Accordingly, the repository no longer stores fuzzy-extractor helper data. The
helper remains local to the owning UAV. The public repository stores only LMS
paths or public tree nodes, while the authenticated root/status service stores
compact root lifecycle records.

The manuscript must also reflect:

- corrected `SID0 = H(Enc(SID0,M0,M1))`
- LM-OTS signing of `Enc(LMOTS-SIGN,mu,q)`
- `SK || K_A^c || K_B^c` as a 96-byte HKDF output
- separate confirmation keys and labels
- the two optional path-delivery profiles
- Mode A direct traffic of 6334 bytes and measured repository traffic
- Mode C direct traffic of 6974 bytes and no runtime path query
- crash-safe NVS reservation rather than unconditional rollback protection
- the still-unresolved unauthenticated-M1 credential-exhaustion limitation
- the physical APUF/FE code and timing as a separate integration component
