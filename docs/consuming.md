# Using Assay in your own Fe contract

Assay is a library before it is an app. Everything the CLI and the deployed
contract do comes from public functions you can import into your own ingot,
and the deployed BeaconProver at
`0xDd356690270534B0DCe6755d77bCA554c9c54603` on mainnet is callable from any
contract today. Every step on this page was built and run before it was
written down.

## 1. Add the dependency

In your project's `fe.toml`, point a dependency at Assay's root:

```toml
name = "gatecheck"
version = "0.1.0"

[dependencies]
verifier = { path = "../assay" }
```

Use a relative path; a git dependency works the same way once you can
reach the repository.

## 2. Call the prover from your contract

This contract accepts a storage claim, asks BeaconProver to verify it against
the beacon root, and keeps the proven value. It compiles exactly as shown:

```fe
use std::abi::{Bytes, Bytes32, DynArray, sol}
use std::evm::{revert_error, Address, Call, Ctx}
use verifier::{Header, ProverMsg}

#[error]
pub struct NotProven { pub slot: u256 }

pub msg GateMsg {
    #[selector = sol(
        "checkSupply(uint64,(uint64,uint64,bytes32,bytes32,bytes32),bytes32,bytes32[],address,bytes[],uint256,bytes[])",
    )]
    CheckSupply {
        timestamp: u64,
        header: Header,
        state_root: Bytes32,
        state_root_branch: DynArray<Bytes32>,
        account: Address,
        account_nodes: DynArray<Bytes>,
        slot: u256,
        storage_nodes: DynArray<Bytes>,
    } -> u256,
}

pub contract SupplyGate uses (call: Call, ctx: Ctx) {
    prover: Address,
    mut last_supply: u256,

    init(assay: Address) uses (mut prover) {
        prover = assay
    }

    recv GateMsg {
        CheckSupply {
            timestamp,
            header,
            state_root,
            state_root_branch,
            account,
            account_nodes,
            slot,
            storage_nodes,
        } -> u256
        uses (call, ctx, prover, mut last_supply)
        {
            let (value, _): (u256, u64) = call
                .static(
                    addr: prover,
                    gas: ctx.gas(),
                    message: ProverMsg::ProveStorage {
                        timestamp,
                        header,
                        state_root,
                        state_root_branch,
                        account,
                        account_nodes,
                        slot,
                        storage_nodes,
                    },
                )
            if value == 0 {
                revert_error(NotProven { slot })
            }
            last_supply = value
            value
        }
    }
}
```

Two things carry the security. The call is `static`, so the prover cannot
change your state. And BeaconProver reverts on any invalid proof, so by the
time `value` reaches your code, every hash from the beacon root down to the
storage slot has been checked inside the EVM.

The same pattern works for the other entry points: `ProveValidator`,
`ProveReceipt`, `ProveLog`, `ProveHistoricalRoot`, `ProveDeepHistoricalRoot`
and `ProvePayload`. The repository's own `ValidatorGate` in `src/example.fe`
is a complete worked consumer that gates on validator records. One thing
to design for in your own gate: the 4788 ring accepts any root from the
last 27 hours, so a proof is a statement about some recent state, not
the newest one. If your policy needs freshness or must never move
backward, compare the proven beacon slot against what you last stored
before acting on it.

## 3. Use the library directly

If you hold a trusted root yourself, you can skip the contract and verify in
your own code. The imports below run in your tests on both backends:

```fe
use verifier::{hash_pair, verify_branch, Branch, GIndex, ProofError, Root}

#[test]
fn the_dependency_verifies_a_real_branch() {
    let left: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111
    let right: u256 = 0x2222222222222222222222222222222222222222222222222222222222222222
    let root = Root::new(hash_pair(left, right))
    match verify_branch(root, leaf: left, gindex: GIndex::new(2), branch: Branch::new([right])) {
        Result::Ok(()) => {},
        Result::Err(_) => core::assert(false),
    }
}
```

The widest doors in the public API: `verify_account`, `verify_storage` and
`verify_trie` for Merkle-Patricia proofs; `verify_branch` and
`verify_payload_multiproof` for SSZ; `verify_validator`,
`verify_historical_root` and `verify_deep_historical_root` for beacon facts;
`verify_receipt` and `verify_log` for transaction outcomes. Every one
returns a `Result` with a named `ProofError`, never a silent failure.

## 4. Run it

```
fe check .
fe test .
fe test --backend native .
```

We built this page's project and ran all three commands against Fe
v26.6.0 before writing it down; everything passed exactly as shown.

## Getting proof data

Your users do not need to build proof arguments by hand. One command
captures, locally verifies, and prints a ready mainnet call:

```
python3 -I tools/prove.py <assay-cli-binary> <address> [slot]
```

The printed arguments are the same ones `CheckSupply` accepts.
