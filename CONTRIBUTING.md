# Contributing

This repository is part of the Quantova post-quantum stack. Before contributing, read `HANDOFF.md`
in the Quantova-Specs repo; `POLICY-crypto.md` there is the supreme law. Any conflict with the crypto
policy → STOP AND REPORT.

## Cryptography (non-negotiable)
Only NIST post-quantum algorithms exist in this stack: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA
(FIPS 205), FN-DSA (on final publication), SHA-3/SHAKE (FIPS 202), 256-bit symmetric, and hash-based
STARKs. Classical cryptography (RSA, DH/DSA, all elliptic curves, all pairings, ecrecover) is
unrepresentable. Banned crates — including transitive and dev-dependencies — are enforced by
`cargo deny check` (see `deny.toml`): k256, ed25519-dalek, curve25519-dalek, p256, secp256k1, rsa,
bls12_381, arkworks pairing crates, openssl EC/RSA. The only exempt repo is Q-Oracle, and nothing
imports it.

## Commits & PRs
- Author only as the owner: `quantova-inc` / `Quantovaorg@gmail.com`. No AI attribution anywhere.
- Conventional Commits (`feat:` `fix:` `spec:` `test:` `bench:` `chore:`). Clean code, minimal
  comments, no slop. Write every commit as if the repo goes public tomorrow.
- Never push to `main`. Branch `feat/<scope>` or `spec/<area>`, open a PR, merge only on green CI.
- Every PR cites the SPEC section it implements. Cross-repo dependencies pin git tags.

## Claims discipline
SAY "sub-second deterministic finality", "100k+ TPS via batch proofs and parallel execution",
"near-trustless Bitcoin deposits", "trust-minimized exits". NEVER "millisecond global finality",
"fully trustless bridge", "quantum-proof".
