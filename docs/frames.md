# Proof-gated frame transactions

Ethereum's next fork, Hegotá, plans a new transaction type called a frame
transaction (EIP-8141). Its validity is decided by contract code instead of
a fixed signature check: a transaction carries a list of frames, and a
VERIFY frame must call the new APPROVE instruction before anything runs or
anyone pays. I built the gate for that seat: a contract that approves
paying for a transaction only when a fact about chain state proves
against a beacon root. The proof chain runs on the live devnet today,
inside an ordinary type 2 transaction that calls the gate, and the frame
transaction that would let the same proof gate the payment was rejected
by the devnet's mempool rules, the gas budget first, with the trace rules
of finding 2 waiting behind it. Both halves are recorded with transaction
hashes and the nodes' own words, in this page and in
`docs/frame_evidence.json`.

The gate reuses the verification library behind the BeaconProver deployed
on mainnet at `0xcB5cAc58273dE7b106E0a2a1387d4F42868E6e7b` and adds two
functions for the devnet's newer fork, `verify_gloas_latest_block_hash`
and `execution_state_root`. The live demonstration runs on
bogota-devnet-2, the public devnet where client teams test the fork.

## What I pinned

Frame transactions are a moving draft, so every moving part is pinned the
same way the rest of this repository pins things.

- EIP-8141 text: commit `dc5d5fa688b7fe87b95a907fcc128b4fde2f4d2f` of
  ethereum/EIPs, last changed 2026-11-01.
- Consensus spec: commit `5165fa360f90f1ea450fd6cd34b29e7da5a4bcc2` of
  ethereum/consensus-specs. `tools/capture_frame.py` decodes the devnet's
  live state with that spec, recomputes the state root, and aborts unless
  it equals the root in the devnet's own header, so the layout I verify
  against is provably the one the devnet runs.
- Devnet: bogota-devnet-2 (chain id 7076643589), run by ethpandaops with
  geth, Nethermind, Besu, reth and ethrex. It is temporary by design, so
  `fixtures/frame_gloas.json` and `docs/frame_evidence.json` record
  everything needed to check the work after the devnet is gone, and
  `tools/capture_frame.py` is written to rerun against a successor
  devnet by changing its two endpoint constants; that rerun is a
  prediction, not a tested fact, until a successor exists.

## The verification chain

The devnet runs the Gloas fork from genesis, and that changed more than a
version number. The Gloas beacon state is a progressive container
(EIP-7495), a new tree shape, and it drops the execution payload header
that my mainnet path reads the state root from. The anchor there is a
field called `latest_block_hash`.

So the gate proves a storage fact in five steps, each one a hash check:

1. Ask the real EIP-4788 contract for the beacon block root at a
   timestamp.
2. Recompute the beacon header root from five claimed fields and require
   it to equal that root.
3. Verify an SSZ branch from the header's state root to the state's
   `latest_block_hash`. The generalized index is computed at compile time
   by `progressive_field` in `src/beacon.fe`, which implements the
   progressive container's subtree walk, and `static_assert` pins the
   result: field 24 of 46 sits at index 2947 under the state root, 23427
   under the beacon root. The committed fixture and the Python oracle both
   confirm it against the live chain.
4. Keccak the supplied execution block header bytes and require the hash
   to equal the proven `latest_block_hash`, then read the execution state
   root out of the header. The hash pins every byte, so the decoder only
   has to locate the field.
5. Walk the Merkle-Patricia proofs for the account and the storage slot,
   and enforce the gate's policy: the account, the slot, and a minimum
   value are fixed when the gate is deployed, not supplied by the caller.

Steps 1, 2 and 5 are the same code the mainnet BeaconProver runs. Steps 3
and 4 are the Gloas additions. The 10 tests in
`src/tests/frame_tests.fe` cover them on both test backends, EVM and
native, and the committed fixture `fixtures/frame_gloas.json` is
self-checking: it proves the 4788 ring buffer's own storage, so the
proven values must equal the block's timestamp and parent beacon root or
the capture refuses to write it.

## The shim

A VERIFY frame approves payment by executing APPROVE (0xaa), an opcode
that exists only in the draft, so no compiler can emit it. I kept the
gap as small as it can be: a 53-byte handwritten shim is the frame's
target, built to forward the frame data to the Fe gate with STATICCALL,
bubble the gate's revert reason if the proof fails, and execute APPROVE
only when the gate accepts. Every byte of verification logic stays in
Fe; the shim holds the call, the branch, and the one opcode. The shim is
deployed, and its APPROVE path has never executed on any chain, because
no node has admitted the frame transaction that would run it; what is
verified about it is its 53 bytes, by the assembler's own checks and by
reading the deployed code back.

`tools/frame_shim.py` assembles it, prints the byte-by-byte listing, and
refuses to emit it if a jump target misses a JUMPDEST, if the APPROVE
operands are out of order, or if the listing stops matching the bytes.

## What implementing this surfaced

Draft EIPs live on implementation feedback, and a heavy validation frame
is exactly the case the current arguments are about. Three findings came
out of this build, and all three carry recorded node answers, committed
in `docs/frame_evidence.json`.

**Proof verification does not fit the public mempool's gas ceiling, and I
have the rejections to show it.** The spec caps public-mempool validation
work at 100,000 gas (`MAX_VERIFY_GAS`), and the open proposal to raise it
(ethereum/EIPs pull 12644; Nethermind merged the 300,000 value in its
pull 15764 and nimbus-eth1 in its pull 5183) stops at 300,000. I
submitted the signed frame transaction twice. With a 1,550,000 gas
validation prefix, the gateway's answer named eleven upstream node
errors, every one "frame transaction validation prefix exceeds the node
verification budget". Resized to a 295,000 gas prefix, inside the
proposed new ceiling, the same eleven answered "frame validation prefix
exceeds gas limit", because every node still enforces the pinned
100,000. The verification itself executes for about 234,000 gas on the
devnet's shallow tries (318,360 minus base and calldata costs, from the
type 2 receipt), and 450,267 gas end to end against mainnet-depth tries
(the `proveStorage` row of `docs/gas.md`, measured against the deployed
mainnet contract). So a proof-gated frame fails the current ceiling
everywhere, mainnet-grade proofs fail even the proposed one, and this
workload class belongs to the alternative mempool (ERC-8421) that was
written for budgets above the public ceiling.

**The ban is structural, not just a gas number.** The pinned revision's
"Validation Trace Rules" and "Banned Opcodes" sections ban TIMESTAMP
during validation-prefix execution and reject any trace that "reads
storage outside `tx.sender`". Reading the 4788 beacon root needs the
contract's storage, and the gate's own policy lives in its storage too.
Raising the gas ceiling therefore would not admit a beacon-anchored
validation frame; proof-gated validity lives in the alternative mempool
by design, and that consequence deserves an explicit sentence in the
mempool section of the EIP.

**The wire format on a live network is already a composition, and the
error for getting it wrong says nothing.** The devnet runs EIP-8250,
which replaces the transaction's `nonce` field with `nonce_keys` and
`nonce_seq`. My first submission, encoded exactly per EIP-8141's own
payload section, was answered with "Invalid params" (code -32602) and
nothing else; the exchange is recorded in `docs/frame_evidence.json`.
Finding the cause means discovering that a second EIP rewrote the first
one's encoding. Implementers need the composed schema in one place, and
a decode error that names the failing field would have turned that
search into one look.

## Running it

The local proof chain needs no network:

```
python3 -I tools/gen_fixtures.py check
fe test .
```

The live path, in order. The faucet needs a browser for its captcha, and
the key step makes a throwaway devnet key that must never touch anything
real:

```
python3 -I tools/frame_devnet.py key <state-dir>
fe build -O 2 --emit bytecode --out-dir <build-dir> .
python3 -I tools/frame_devnet.py deploy <state-dir> <build-dir>/FrameGate.bin
<consensus-specs-venv-python> -I tools/frame_devnet.py send <state-dir> <consensus-specs>
python3 -I tools/frame_devnet.py status <state-dir>
```

`send` captures a fresh anchor, checks the whole proof against the
deployed gate with a plain eth_call first, then builds, signs and submits
the type 0x06 transaction with the `[only_verify, pay]` shape the spec
defines.

## Live evidence

Everything below happened on bogota-devnet-2 on 2026-11-20 and can be
checked on its explorer at https://dora.bogota-devnet-2.ethpandaops.io
while the devnet lives.

- Storage target: `0x5d93Aa46a0fD608028b1784f3531C835ed5322C0`, a
  seven-byte contract whose slot 0 holds 42.
- FrameGate: `0xC0806B8F67C8EE993254d2C943DA3A187BcBe891`, the Fe
  verifier, deployed watching that slot with a floor of 1.
- Pay shim: `0xd00EC054386D4C0bD6B5BBEFFbAe488939c87214`, the 53-byte
  APPROVE shim, funded to pay.
- Proof verified on chain, in an ordinary type 2 transaction calling the
  gate directly:
  `0xcde3bf0e71bfce9d5e221cdb64a5bdef12d4ebc246762c78af36d7080d8b6813`,
  block 157718, status success, 318,360 gas, of which about 63,500 is
  calldata for the 4,740-byte proof and about 234,000 is the verification
  itself. The gate returned 42, the proven value, after walking every
  hash from the live 4788 beacon root to the storage slot.
- Validity gating refused: the signed type 0x06 transaction
  `[only_verify, pay]` was rejected at a 1,550,000 gas prefix as "frame
  transaction validation prefix exceeds the node verification budget"
  and at a 295,000 gas prefix as "frame validation prefix exceeds gas
  limit", each time with eleven upstream node errors behind the
  gateway's answer. The raw signed transaction and all three exchanges,
  the EIP-8250 decode rejection included, are committed in
  `docs/frame_evidence.json`, so the evidence outlives the devnet.

So the state of things, exactly: the proof chain runs on the frames
devnet inside an ordinary transaction, and the frame path that would let
the same proof approve the payment was refused at the mempool door, by
the budget first, with the trace rules of finding 2 behind it; the
APPROVE step itself therefore remains unexecuted.

## Honest limits

The EIP is a draft at the stage where even constants are moving, so this
work is pinned to a revision, not to the fork. The devnet is temporary and
its predecessors were torn down within weeks; the fixture, the oracle and
the capture tool exist so the claim outlives the chain it ran on. And the
devnet's nodes all enforce the public mempool rules, so no path on it
admits an over-budget frame today; the alternative mempool (ERC-8421) is
the designed home for this class, and the evidence section records
exactly what every node said when asked.
