# How this repository audits itself

This page says what we checked, how we checked it, what the checks found
along the way, and what we still do not claim. The findings section is
real. A self-audit that only lists passes is marketing.

## The bar every proof path clears

Before any proof kind was called done, it cleared five gates, and the
gates stay in CI so they keep clearing them.

1. **A fixture from a real network.** Every committed fixture was
   captured from mainnet, from the frames devnet, or from a specification
   build, and records where it came from. Nothing is hand-written.
2. **An independent oracle.** For each path a plain Python implementation
   that shares no code with the Fe verifier recomputes the same answer.
   The fixture generators refuse to emit test data the oracle disagrees
   with, so the Fe tests can never inherit a shared mistake.
3. **Tamper tests.** Each path's tests flip branch words, reuse proofs at
   neighbouring positions, truncate node lists and corrupt encodings, and
   require the exact named refusal, not just any failure.
4. **Both compile targets.** The suite runs on the EVM backend and the
   native backend, 168 and 130 tests, and the browser module reproduces
   every committed verdict a third time.
5. **Outside references where they exist.** The trie walk is checked
   against the ethereum/tests vectors and the execution specification.
   SSZ roots are checked against the consensus spec's own test vectors.
   The leanXMSS verifier agrees with all 40 of EthLib's vectors. The
   receipts builder must reproduce real blocks' receipt roots exactly.

## What the checks caught

These are the bugs and weak points our own gates and reviews found in
our work before anything shipped. Each one was fixed the same day it was
found.

- The gas benchmark once compared a Solidity baseline that skipped call
  scaffolding the Fe side paid for. The honest recomputation changed a
  headline number from flattering to accurate.
- A deep-history test was wrong while the verifier was right. A skipped
  slot at the Capella boundary legitimately copies the previous root
  forward, and the test had assumed it could not.
- The browser anchor engine had a concurrency race in its zero-hash
  cache that corrupted exactly the four most parallel fields. The
  self-check that refuses any root not matching the chain's caught it on
  the first live block.
- The WebAssembly wrapper mis-parsed one header field in a way that
  worked for every committed proof but would have rejected a legitimate
  empty-branch proof. A hostile review caught it before commit.
- Early site wording claimed more than the evidence held in three
  places, including a sentence that implied a rejected transaction had
  succeeded. Reviews rewrote every such sentence to match the record.
- The daily pipeline could have discarded a finished harvest when a
  later step failed, and two pipelines could race each other's commits.
  Both were restructured before the race ever fired.

## What the public record holds

Claims live outside this repository where anyone can check them.

- The mainnet contract, its deployment and its first proof are
  transactions on Ethereum, listed in [deployment.md](deployment.md).
- The Provenance workflow rebuilds the contract from source with the
  pinned compiler and matches the chain's bytes, and rebuilds the Fe
  compiler itself from source to reproduce the browser module. Its runs
  are public, and the Linux rebuild reproducing bytes first built on a
  Mac also settles that the output is deterministic across machines.
- The pipelines that keep the site's proofs fresh commit their results
  with timestamps, so the claim that this runs unattended has a log.
- The frames devnet evidence, including every node's rejection message,
  is committed in [frame_evidence.json](frame_evidence.json) with the
  raw signed transaction, so it outlives the devnet it ran on.

## What we do not claim

- Proofs reach the Capella fork and no further back.
- A live verification needs a beacon root younger than about 27 hours,
  the depth of the 4788 ring buffer.
- The receipt decoder fails closed on transaction types above 4.
- The frame gate and the post-quantum work implement pinned revisions of
  moving drafts, and both say so where they are described.
- The state access rules of the frame specification were read, not
  triggered, because the gas check rejected our transaction first. The
  one finding we could not demonstrate live was removed from our
  write-up rather than kept on the strength of reading.
- Fe has no fuzzer, so adversarial coverage is the committed suites and
  tamper tests. Random cross-fuzzing of the XMSS verifier against the
  reference implementation is the known next hardening step.
