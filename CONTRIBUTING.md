# Contributing to Quantova

Quantova is a post quantum Layer 1. Its code moves real value once mainnet is live, so every change is held to the standard of a tier one blockchain. These rules apply to every repository in the Quantova organisation. Please read all of them before you open a pull request.

## 1. Who can change what

1. Only the maintainers in the Quantova maintainers team can merge. Nobody else has write access to any repository.
2. Nobody pushes to main. Every change arrives through a pull request from a fork.
3. Main cannot be force pushed, rewritten or deleted.
4. Release tags are created by maintainers only and can never be moved or deleted once published.
5. Every path in every repository is owned by the maintainers team through CODEOWNERS, and a code owner must approve every pull request.

## 2. Before you write code

1. Open an issue first for anything larger than a small bug fix or a documentation correction. Explain the problem, not only the solution. A pull request for a change nobody agreed to may be closed without review.
2. Changes to consensus, finality, validator selection, staking, slashing, fees, governance, the token supply, the virtual machine or the cryptography need an accepted Quantova Improvement Proposal before any code is reviewed.
3. Block finality and throughput are fixed properties of the network. A change that makes finality slower or lowers throughput is not accepted, whatever else it improves. Changes on the block path must include benchmark results taken before and after on the same machine.
4. Only the NIST post quantum algorithms are allowed. These are ML KEM from FIPS 203, ML DSA from FIPS 204, SLH DSA from FIPS 205 and SHA 3 and SHAKE from FIPS 202, together with 256 bit symmetric primitives and hash based STARKs. A change that adds classical public key cryptography, directly or through a dependency, is closed.

## 3. Requirements for every pull request

A pull request is reviewed only when all of the following hold.

1. Every commit is signed and shows as Verified on GitHub. Unsigned commits cannot be merged.
2. Every check is green. This includes formatting, lints with warnings treated as errors, the full test suite, coverage, the dependency and licence policy, secret scanning and the pin checks.
3. The pull request does one thing. Refactors, formatting and behaviour changes go in separate pull requests.
4. The description says what changed, why it changed, how it was tested and which specification section or issue it relates to.
5. New behaviour comes with tests, and a bug fix comes with a test that fails before the fix and passes after it.
6. Public interfaces, wire formats, storage layouts and hashing domains do not change unless the issue or proposal agreed it.
7. The branch is up to date with main and every review conversation is resolved.
8. The AI disclosure in the pull request template has exactly one box ticked. A pull request that says AI tools helped write it is flagged by an automatic check and receives a line by line review. Not disclosing AI help is a reason to close the pull request.

## 4. Commits

1. Write commit messages in plain sentences that say what the commit does.
2. Use your own name and an email address you control. Commits must not carry other authors, generated trailers or tool attribution.
3. Do not commit secrets, keys, seeds, recovery phrases, private endpoints or personal data. Secret scanning blocks pushes that contain them, and any leaked secret is treated as compromised.
4. Do not commit build output, binaries, editor files or local test data.

## 5. Dependencies

1. A new dependency needs a written reason in the pull request and the approval of a maintainer.
2. Dependencies are pinned. Rust crates are locked in Cargo.lock, npm packages are pinned exactly with a lockfile, and other Quantova repositories are pinned by full commit or release tag.
3. Every dependency must carry a licence compatible with Apache 2.0 and MIT and must pass the dependency policy in the repository.
4. Dependencies from unknown registries, git branches or unpinned sources are not accepted.

## 6. Workflows and automation

1. Changes under the .github folder, build scripts, release scripts and packaging files are reviewed with the same care as protocol code.
2. Workflows run with read only tokens by default, and third party actions are pinned by full commit.
3. Workflows from a fork run only after a maintainer approves them, and they never receive repository secrets.
4. Publishing to npm, PyPI or crates.io happens only from the release workflow of the official repository, never from a contributor machine.

## 7. Review

1. A code owner reviews every pull request. Changes to consensus, cryptography, the virtual machine, the prover, bridges and SDK signing receive the deepest review and may take longer.
2. A new push after an approval dismisses that approval, and the latest push must be approved again before merge.
3. Maintainers may ask for changes, split a pull request, or close it if it does not meet these rules.
4. Approval of one pull request does not carry over to any other.

## 8. Security

Never report a vulnerability in a public issue, discussion or pull request. Follow SECURITY.md and use private vulnerability reporting under the Security tab of the affected repository.

## 9. Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0 and the MIT licence, at the choice of the user, the same terms as the rest of the project.

## 10. Conduct

Everyone taking part follows CODE_OF_CONDUCT.md. Keep discussion respectful and focused on the work.
