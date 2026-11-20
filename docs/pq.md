# Assay and post-quantum Ethereum

Ethereum is preparing for a world with quantum computers. A large enough one
would break the BLS signatures that secure consensus
today. So the protocol is rebuilding its trust on hash functions alone:
validators would sign with leanXMSS, a scheme whose security rests only on
the hash. This work is live.
The specification sits on the `pq` branch of ethereum/consensus-specs and
changes daily, client teams are wiring it up, and the first post-quantum
devnets are running.

## Why Assay survives the transition unchanged

Assay verifies zero signatures. Its whole trust chain is hashing: SHA-256
for the beacon's SSZ trees, Keccak-256 for the execution tries. Those are
the primitives the post-quantum design keeps, and hash
collision resistance is the one assumption it reduces all of consensus to. When
BLS goes, every BLS-dependent light client and bridge must be rebuilt;
every Assay proof keeps verifying as it does today.

leanXMSS itself hashes with Keccak-256, Ethereum's own hash and a native
EVM operation this codebase already uses on every trie node.

## Evidence, not posture

The claims above are tested in this repository, against a beacon state that
Ethereum's own executable post-quantum specification built. The fixture
`fixtures/pq_state.json` records the exact spec commit it was generated
against, and `tools/gen_pq_fixture.py` regenerates it in one command when
the draft moves.

- The post-quantum state is a progressive container, a new SSZ layout with
  different generalized indices. Assay's verifier walked it without a single code change.
  The committed tests prove a validator's XMSS public key, the new
  vrf_root beside it, the whole nine-field validator record, and the
  chain's genesis root, each from the post-quantum state root.
- Fe computes the new nine-field validator record root itself, through the
  `PqValidator` container, and it equals the spec's answer byte for byte.
- Forgeries fail the same way they fail today: a flipped key, a reused
  branch at a neighbouring position, and a corrupted branch word are each
  refused in the committed tests.
- Our independent Python oracle verifies the same fixture with no
  post-quantum tooling involved, which is the point: these are ordinary
  hash proofs, and ordinary hash proofs are the post-quantum plan.

## What changes when the fork is real

Three things, all small and all in places this codebase was built to change:

1. New generalized indices for the reshaped state. Ours are computed by
   `const fn` and pinned by `static_assert`, so the update is new constants
   checked by the compiler and the oracle, not a rewrite.
2. The validator container gains a field and loses none of its shape. The
   `PqValidator` container here already matches the draft.
3. The anchor stays the same idea: one 32-byte root the protocol publishes.
   Everything below it remains hashing.

One honest caveat: the `pq` branch is a moving draft. The fixture is
labeled with its spec commit, and a layout change upstream means one rerun
of the generator, which is the cost of being early.

## Where user accounts fit

This page covers consensus. For user transactions, the planned path to
post-quantum signatures is EIP-8141 frame transactions, where a validation
frame can verify any signature scheme. That is an execution-layer change.
Our receipt decoder deliberately
refuses transaction types it does not know. When the new type ships,
supporting it is a one-constant change with a new fixture, and nothing
before then verifies wrongly.
