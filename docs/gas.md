# Gas

Measured with the compiler's own harness, `fe bench`, which compiles each fixture's Fe and Solidity sides, deploys each on a fresh EVM, and reports the gas of one call. Raw numbers include the 21,000 intrinsic transaction cost and the 4-byte selector on both sides. The committed CSV is `docs/gas_benchmark.csv`; CI regenerates it and fails on any difference.

## Environment

| Component | Version |
|---|---|
| Fe | 26.6.0 (5b3f96a), release binary |
| solc | 0.8.30+commit.73712a01 |
| Harness | `fe bench`, Fe at `-O 2`, Solidity at the best of legacy and via-IR, optimizer off and on |

## Method

`fe bench` cannot pass arrays as call arguments, so every fixture embeds its proof as constants and exposes two argument-free calls: `verify()` runs the full verification and reverts unless the result equals the oracle-checked value, and `baseline()` builds the same inputs without verifying. The verification cost of a fixture is `verify - baseline` within the same column. Proof bytes are embedded as packed 32-byte words on the Fe side and as hex literals on the Solidity side, the cheapest idiomatic loading on each. The fixtures are generated from the committed library sources and mainnet fixtures by `tools/gen_bench.py`; `gen_bench.py check` fails CI if they drift.

Comparison code, vendored byte for byte under `bench/vendor/` with licenses:

| Baseline | Source | License |
|---|---|---|
| `EthereumTrie.flat.sol` | polytope-labs/solidity-merkle-trees @ 6bbc83d5ac33f85761725cf2eba4f8700164e8ba, `forge flatten src/EthereumTrie.sol` (byte-reproducible) | Apache-2.0 |
| `SSZ.sol` | madlabman/eip-4788-proof @ 20ec51c3215214a3aa61e1281d4be90c48ede3c9, unchanged | MIT |

Both the vendored SSZ verifier and Lido's Community Staking Module verifier are derived from Solady's MerkleProofLib, as their own source comments and licenses state. Lido's was not used because it is GPL-3.0 and its current head needs edits to compile with solc 0.8.30. The vendor files' SHA-256 hashes are pinned in `tools/gen_bench.py`, so CI fails if any vendored byte changes.

## Results (fe 26.6.0, solc 0.8.30)

| Fixture | Fe verify | Fe baseline | Fe net | Sol best verify | Sol best baseline | Sol net | Fe net vs Sol net |
|---|---|---|---|---|---|---|---|
| mpt_account (USDC account, 9 nodes, 3,847 proof bytes) | 252,861 | 33,931 | 218,930 | 856,823 | 25,818 | 831,005 | -74% |
| mpt_storage (WETH slot 0, 7 nodes) | 198,123 | 30,854 | 167,269 | 639,081 | 24,930 | 614,151 | -73% |
| ssz_payload (12-level branch) | 29,202 | 23,122 | 6,080 | 29,041 | 24,678 | 4,363 | +39% |
| ssz_validator (validator record root + 50-level branch) | 60,217 | 32,647 | 27,570 | 52,858 | 36,089 | 16,769 | +64% |

Reading guide:

- The Merkle-Patricia verifier is 3.2x to 3.4x cheaper than Polytope's generic trie library on raw calls and 3.7x to 3.8x cheaper net of setup. Both sides verify the same mainnet proofs against the same roots and check the resulting values.
- The SSZ raw calls are within 0.6% (payload) and 14% (validator) of the baseline. Net of setup the baseline wins, because it is hand-tuned assembly from Solady while Assay's verifier is ordinary high-level Fe; the absolute difference is 1.7k to 10.8k gas per call.
- Both validator baselines build the record and compute its hash tree root, so the net numbers isolate the 50-level branch walk on each side.
- The Solidity SSZ baseline must receive its branch as calldata, so both of its calls make one external self-call; its baseline subtracts that overhead.

Caveats:

- Proofs are embedded, not passed as calldata, so real transactions add calldata gas on top for both languages equally. Since EIP-7623 (Pectra), a transaction pays the larger of the standard cost (4 gas per zero calldata byte, 16 per non-zero, plus execution) and the calldata floor (10 gas per token); for proof-carrying calls with little other execution the floor can bind.
- The account fixture is not perfectly symmetric: Assay decodes the account leaf into nonce, balance and both roots and checks each; Polytope returns the raw RLP value, which the fixture only hashes and compares.
- A buffer-reuse variant of the hash loop (one shared 64-byte buffer, `std::evm::crypto::sha256`) was measured about 200 gas per level WORSE than `std::evm::ssz::hash_pair` and discarded; std's path is already minimal.

## End-to-end contract calls

Measured inside `fe test` with `evm.gas()` around a real call to the deployed `BeaconProver` (mainnet fixture data, mock EIP-4788 contract). These are execution-only numbers: no 21k intrinsic and no calldata gas, because the harness calls the contract from another contract.

| Call | Gas at -O 1 | Gas at -O 2 | What it covers |
|---|---|---|---|
| `proveStorage` (USDC slot 0) | 452,487 | 450,267 | 4788 lookup, header root, 12-level SSZ branch, account trie (9 nodes), storage trie (8 nodes), full ABI decode |
| `proveValidator` (whole record) | 38,511 | 38,158 | 4788 lookup, header root, pubkey root, record root, 50-level SSZ branch |

`src/tests/gas_tests.fe` keeps both calls inside recorded bands (300k-600k and 25k-60k), so a large regression fails the suite.

## Reproduce

The exact values were read by replacing each band assert with `core::panic_code(used)` in a scratch copy and running `fe test -f gas_stays` at each level; the committed test keeps the bands.

```sh
.venv-capture/bin/python3 -I tools/gen_bench.py check
fe bench bench --solc <solc-0.8.30> -o out
diff out/gas_benchmark.csv docs/gas_benchmark.csv
fe test -f gas_stays
```
