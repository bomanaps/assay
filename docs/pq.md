# Assay and post-quantum Ethereum

Ethereum is getting ready for quantum computers. A big enough one could
forge the BLS signatures that secure the chain today. So researchers are
moving consensus onto hash-based signatures called leanXMSS, which only
depend on the hash function staying strong. This is already happening: the
spec is being written on the `pq` branch of ethereum/consensus-specs,
client teams are implementing it, and the first test networks are running.

## Why Assay survives the transition unchanged

Assay never checks a signature. Everything it does is hashing, SHA-256 on
the beacon side and Keccak-256 on the execution side, and those are the
same hashes the post-quantum design keeps. So when BLS is replaced, tools
built on BLS have to be rebuilt, while Assay's proofs keep working exactly
as they do now.

leanXMSS itself hashes with Keccak-256, Ethereum's own hash. We already
use it on every trie node we verify.

## We tested it

We did not just reason about this, we tested it. We used Ethereum's own
draft code for the quantum fork to build a real beacon state in the new
format, then ran our verifier against it. The fixture
`fixtures/pq_state.json` records the exact spec commit it came from, and
`tools/gen_pq_fixture.py` rebuilds it in one command when the draft moves.

- The post-quantum state is a progressive container, a new SSZ layout with
  different generalized indices. Our verifier handled it without us changing a single line.
  The committed tests prove a validator's XMSS public key, the new
  vrf_root beside it, the whole nine-field validator record, and the
  chain's genesis root, each from the post-quantum state root.
- Fe computes the new nine-field validator record root itself, through the
  `PqValidator` container, and it equals the spec's answer byte for byte.
- Forgeries fail the same way they fail today. Our tests flip a key, reuse
a branch at a neighbouring position, and corrupt a branch word, and the
verifier refuses all three.
- Our independent Python oracle verifies the same fixture with no
  post-quantum tooling involved.

## What changes when the fork is real

When the fork actually ships, three small things change on our side, and
all three live in places we designed to be changed:

1. New generalized indices for the reshaped state. Ours are computed by
   `const fn` and pinned by `static_assert`, so the update is new constants
   checked by the compiler and the oracle, not a rewrite.
2. The validator container gains a field and loses none of its shape. The
   `PqValidator` container here already matches the draft.
3. The anchor stays the same idea: one 32-byte root the protocol publishes.
   Everything below it remains hashing.

One honest caveat: the `pq` branch is a moving draft. The fixture is
labeled with its spec commit, and a layout change upstream means one rerun of the generator.

## Where user accounts fit

This page covers consensus. For user transactions, Ethereum plans to use
EIP-8141 frame transactions, where a validation frame can verify any
signature scheme. That is an execution-layer change.
Our receipt decoder deliberately
refuses transaction types it does not know. When the new type ships,
supporting it is a one-constant change with a new fixture, and nothing
before then verifies wrongly.
