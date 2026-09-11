# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | Toy / research — use only with pinned roots and cleartext-query awareness |
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
