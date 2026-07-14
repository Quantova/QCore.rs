# Contributing

This repository is part of the Quantova post quantum stack. Before you contribute, read the crypto policy and the handoff in the Quantova Specs repository. The crypto policy is the supreme law. If anything you are asked to do conflicts with it, stop and report.

## Cryptography

Only the NIST post quantum algorithms exist in this stack. These are ML KEM from FIPS 203, ML DSA from FIPS 204, SLH DSA from FIPS 205, FN DSA once it is final, SHA 3 and SHAKE from FIPS 202, the 256 bit symmetric primitives, and hash based STARKs. Classical cryptography cannot be expressed. The banned crates, including transitive and development dependencies, are enforced by cargo deny using the deny file. The one exempt repository is Q Oracle, and nothing imports it.

## Commits and pull requests

Author every commit as the repository owner only, with no other attribution anywhere. Write clean code with few comments and no filler. Never push straight to main. Work on a feature branch, open a pull request, and merge only when the checks are green. Every pull request names the specification section it implements. Cross repo dependencies pin git tags.

## Claims discipline

Say sub second deterministic finality, one hundred thousand or more transactions per second through batch proofs and parallel execution, near trustless Bitcoin deposits, and trust minimized exits. Never say millisecond global finality, fully trustless bridge, or quantum proof.
