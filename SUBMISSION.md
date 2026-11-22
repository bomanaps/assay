# Submission

Entry FE-024 in the Fe Builders Challenge.

## Pitch

Assay proves any fact about Ethereum, any age, from one 32-byte beacon
root, in Fe that is deployed on mainnet, verified live by anyone's
browser, and provably the pinned compiler's own output.

## What to submit on the day

- Repository: https://github.com/bomanaps/assay
- Commit SHA and tag: recorded at tagging time
- Compiler: fe 26.6.0 (5b3f96a), with Fe master `2e9a011df` for the
  browser module only, both pinned and gated in CI
- License: Apache-2.0
- Demo: https://bomanaps.github.io/assay/ and its Run page, plus the
  video linked from the site

## Starting point

The repository began at commit
[`3c6a5664`](https://github.com/bomanaps/assay/commit/3c6a56642f58dcc65add98f973c52cf1b17f5de6)
on 2026-11-05 holding a license and a one-line readme and nothing else. Every line of code,
test, fixture, document and pipeline was written inside the challenge
window. The git history is the record.

## Third-party code and data

Everything not written for this entry, and where it lives.

| What | License | Where and why |
|---|---|---|
| Polytope Labs solidity-merkle-trees | Apache-2.0 | vendored in `bench/*.sol` as the Solidity baseline the gas benchmark compares against, never in the verifier |
| fe-lang/json ingot | Apache-2.0, pinned by revision | dependency of the native CLI only, for reading fixture files |
| marked.js 9.1.6 | MIT | renders Markdown on the site's Docs page, loaded from cdnjs |
| ethereum/tests trie vectors | MIT | vendored under `fixtures/ethereum_tests`, conformance input for the trie walk |
| consensus-spec-tests vectors | MIT | vendored under `fixtures/consensus_spec`, conformance input for SSZ roots, re-downloaded and diffed in CI |
| EthLib leanXMSS vectors | CC0-1.0 | vendored under `fixtures/xmss`, conformance input for the signature verifier, re-downloaded and diffed in CI |
| remerkleable, pycryptodome | MIT, BSD | Python capture and oracle tooling under `tools/`, never part of the verifier |
| ethereum/execution-specs | CC0-1.0 | pinned reference the trie oracle is cross-checked against in CI |
| noble is not used | | the browser engines in `docs/` are hand-written for this entry |

The verifier itself, everything under `src/`, `cli/src` and `wasm/src`,
has no dependencies beyond Fe's own standard library.

## AI assistance

I wrote and edited parts of the code myself and directed every design
decision, deployment and review, with Claude, an AI pair programmer,
drafting code, tests and documentation under my instruction throughout.
The adversarial reviews described in [docs/audit.md](docs/audit.md) were
also AI-run at my request, and I reviewed what shipped.

## Team

bomanaps.
