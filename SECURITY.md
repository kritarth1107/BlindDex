# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.6.x | Toy / research — query receipts + answer padding; demo anti-replay only, not production crypto |
| 0.5.x | Toy / research — sync handshake + epoch binding; use with pinned seal/root and cleartext-query awareness |
| 0.4.x | Toy / research — public directories; use with pinned seal and cleartext-query awareness |
| 0.3.x | Toy / research — offline hints; use with pinned roots and cleartext-query awareness |
| 0.2.x | Toy / research — Merkle proofs; use with pinned roots and cleartext-query awareness |
| 0.1.x | Toy / research |

BlindDex is **not** a production PIR deployment. Do not rely on the toy query
path for index privacy.

## Reporting a vulnerability

Email **singhalkritarth@gmail.com** with:

- Affected commit / tag
- Description and impact
- Minimal reproduction if possible

Please allow reasonable time before public disclosure.

## Known limitations (not bugs)

See [`THREAT_MODEL.md`](THREAT_MODEL.md). In particular:

- Exact one-hot queries reveal the index on the wire.
- JSON wire codec does not encrypt or obfuscate queries.
- Merkle proofs authenticate catalog membership under a pinned root; they do
  not replace transport security or server authentication.
