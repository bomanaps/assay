"""Render the gas benchmark fixtures under bench/ from committed sources.

usage: gen_bench.py generate
       gen_bench.py check

Each fixture is a pair fe bench can run: one standalone .fe file, one .sol
file, and a .toml manifest naming the calls. fe bench cannot import this
ingot and cannot pass arrays as call arguments, so the .fe side is the
committed library source concatenated into one file (ingot imports dropped,
pub(ingot) widened, std and core imports deduplicated) plus the proof
embedded as packed word constants, and every call takes no arguments. The
.sol side is a vendored third-party verifier, byte for byte, plus an
appended wrapper holding the same proof.

Vendored baselines, both unmodified, licenses alongside:
- bench/vendor/EthereumTrie.flat.sol: polytope-labs/solidity-merkle-trees
  commit 6bbc83d5ac33f85761725cf2eba4f8700164e8ba, Apache-2.0, produced by
  `forge flatten src/EthereumTrie.sol` (reproducible byte for byte).
- bench/vendor/SSZ.sol: madlabman/eip-4788-proof commit
  20ec51c3215214a3aa61e1281d4be90c48ede3c9, MIT, src/SSZ.sol unchanged.
  Lido's audited CSM verifier descends from this code.

Every fixture exposes verify() and baseline(): baseline builds the same
inputs without verifying, so reports can subtract the setup cost. The SSZ
Solidity verifier demands calldata, so its wrapper self-calls externally and
baseline makes the identical external call to a no-op with the same
arguments. Both sides revert unless the proof yields the oracle's values.

generate refuses to write unless every rendered .fe fixture passes
`fe check` (the FE environment variable names the compiler binary) and no
ingot:: reference survives concatenation. check regenerates in memory and
exits nonzero on any difference, so CI proves bench/ matches src/ and
fixtures/.
"""

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt
import oracle_ssz

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
FIXTURES = ROOT / "fixtures"
BENCH = ROOT / "bench"
VENDOR = BENCH / "vendor"

VENDOR_SHA256 = {
    "EthereumTrie.flat.sol": "5a1004a270fe00d294002b7def99d4d0b0b520aaf911b975d6b6fa49d4ed68eb",
    "LICENSE.polytope": "d8ddd6435eae4d5e7df65248f19a347fcf67e2d454d0826cb418a33648e2dd54",
    "SSZ.sol": "997d93e6f4b49b59a4773e5e5648262bc81391edfdde1af12761041a65b63172",
    "LICENSE.madlabman": "203905b43e82b98412a20d3f9a92c3277a48c1758cbaa7870d9c7b64daaf333b",
}


def check_vendor():
    for name, expected in VENDOR_SHA256.items():
        path = VENDOR / name
        if not path.exists():
            raise SystemExit(f"error: vendored file {name} is missing")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"error: vendored file {name} differs from the pinned upstream hash")
    extra = sorted(p.name for p in VENDOR.iterdir() if p.name not in VENDOR_SHA256)
    if extra:
        raise SystemExit(f"error: unexpected files under bench/vendor: {', '.join(extra)}")


MPT_ORDER = ("types.fe", "nibbles.fe", "mpt.fe", "account.fe", "storage.fe", "fixture_support.fe")
SSZ_ORDER = ("types.fe", "ssz.fe", "beacon.fe", "fixture_support.fe")


def concatenate(order):
    imports = set()
    bodies = []
    for name in order:
        kept = []
        for line in (SRC / name).read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("use ingot::"):
                continue
            if stripped.startswith("use core::") or stripped.startswith("use std::"):
                imports.add(stripped)
                continue
            kept.append(line.replace("pub(ingot) ", "pub "))
        bodies.append("\n".join(kept).strip("\n"))
    text = "\n".join(sorted(imports)) + "\n\n" + "\n\n".join(bodies) + "\n"
    if "ingot::" in text:
        raise SystemExit("error: an ingot:: reference survived concatenation")
    return text


def words_of(data):
    padded = bytes(data) + bytes(-len(data) % 32)
    return [padded[i : i + 32] for i in range(0, len(padded), 32)]


def fe_word_array(name, chunks):
    body = "\n".join(f"    0x{chunk.hex()}," for chunk in chunks)
    return f"const {name}: [u256; {len(chunks)}] = [\n{body}\n]\n"


def fe_usize_array(name, values):
    return f"const {name}: [usize; {len(values)}] = [{', '.join(str(v) for v in values)}]\n"


def fe_nodes_harness(nodes):
    flat = bytearray()
    offsets = [0]
    for node in nodes:
        flat.extend(node)
        offsets.append(len(flat))
    parts = [
        fe_word_array("BENCH_NODE_WORDS", words_of(flat)),
        f"const BENCH_NODE_LEN: usize = {len(flat)}\n",
        fe_usize_array("BENCH_OFFSETS", offsets),
        f"const BENCH_NODE_COUNT: usize = {len(nodes)}\n",
        """
struct BenchNodes {
    bytes: MemBuffer,
}

impl ProofNodes for BenchNodes {
    fn count(self) -> usize {
        BENCH_NODE_COUNT
    }

    fn node(self, _ index: usize) -> ref MemSpan {
        let start = BENCH_OFFSETS[index]
        self.bytes.span().slice(offset: start, len: BENCH_OFFSETS[index + 1] - start)
    }
}

fn bench_nodes() -> BenchNodes {
    BenchNodes { bytes: load_packed(BENCH_NODE_WORDS, len: BENCH_NODE_LEN) }
}

fn bench_checksum() -> u256 {
    let nodes = bench_nodes()
    var total: usize = 0
    var i: usize = 0
    while i < nodes.count() {
        total += nodes.node(i).len()
        i += 1
    }
    total as u256 + nodes.count() as u256
}
""",
    ]
    return "".join(parts)


FE_MSG = """
pub msg BenchMsg {
    #[selector = sol("verify()")]
    Verify -> u256,
    #[selector = sol("baseline()")]
    Baseline -> u256,
}
"""

SOL_NODE_HELPERS = """
    function benchProof() internal pure returns (bytes[] memory proof) {
        bytes[] memory nodes = new bytes[](NODE_COUNT);
{assign}
        proof = nodes;
    }

    function benchChecksum() internal pure returns (uint256 total) {
        bytes[] memory proof = benchProof();
        for (uint256 i = 0; i < proof.length; i++) {
            total += proof[i].length;
        }
        total += proof.length;
    }
"""


def sol_nodes(nodes):
    assigns = "\n".join(f'        nodes[{i}] = hex"{node.hex()}";' for i, node in enumerate(nodes))
    helpers = SOL_NODE_HELPERS.replace("{assign}", assigns)
    return f"    uint256 internal constant NODE_COUNT = {len(nodes)};\n{helpers}"


def render_trie_fe(kind, result):
    text = concatenate(MPT_ORDER)
    if kind == "account":
        address = result["address"]
        consts = [
            fe_word_array("BENCH_ADDRESS_WORD", [address + bytes(12)]),
            f"const BENCH_STATE_ROOT: u256 = 0x{result['state_root'].hex()}\n",
            f"const BENCH_NONCE: u64 = {result['nonce']}\n",
            f"const BENCH_BALANCE: u256 = {result['balance']}\n",
            f"const BENCH_STORAGE_ROOT: u256 = 0x{result['storage_root'].hex()}\n",
            f"const BENCH_CODE_HASH: u256 = 0x{result['code_hash'].hex()}\n",
            fe_nodes_harness(result["nodes"]),
        ]
        verify = """
        Verify -> u256 {
            var address: [u8; 20] = [0; 20]
            let word = BENCH_ADDRESS_WORD[0]
            var i: usize = 0
            while i < 20 {
                address[i] = ((word >> (8 * (31 - i)) as u256) & 0xff).downcast_truncate()
                i += 1
            }
            match verify_account(
                state_root: StateRoot::new(BENCH_STATE_ROOT),
                address,
                nodes: bench_nodes(),
            ) {
                Result::Ok(Proven::Present(account)) => {
                    core::assert(account.nonce == BENCH_NONCE)
                    core::assert(account.balance == BENCH_BALANCE)
                    core::assert(account.storage_root == StorageRoot::new(BENCH_STORAGE_ROOT))
                    core::assert(account.code_hash == CodeHash::new(BENCH_CODE_HASH))
                    account.balance + 1
                },
                _ => core::panic_code(1),
            }
        }
"""
    else:
        slot = result["slots"][0]
        consts = [
            f"const BENCH_STORAGE_ROOT: u256 = 0x{result['storage_root'].hex()}\n",
            f"const BENCH_SLOT: u256 = 0x{slot['key'].hex()}\n",
            f"const BENCH_VALUE: u256 = {slot['value']}\n",
            fe_nodes_harness(slot["nodes"]),
        ]
        verify = """
        Verify -> u256 {
            match verify_storage(
                storage_root: StorageRoot::new(BENCH_STORAGE_ROOT),
                slot: BENCH_SLOT,
                nodes: bench_nodes(),
            ) {
                Result::Ok(value) => {
                    core::assert(value == BENCH_VALUE)
                    value + 1
                },
                Result::Err(_) => core::panic_code(1),
            }
        }
"""
    contract = f"""{FE_MSG}
pub contract AssayBench {{
    recv BenchMsg {{{verify}
        Baseline -> u256 {{
            bench_checksum()
        }}
    }}
}}
"""
    return text + "\n" + "".join(consts) + contract


def sol_wrapper(body):
    return f"\ncontract AssayBench {{\n{body}}}\n"


def render_trie_sol(kind, result):
    vendor = (VENDOR / "EthereumTrie.flat.sol").read_text()
    if kind == "account":
        key_source = f'abi.encodePacked(keccak256(hex"{result["address"].hex()}"))'
        expected = oracle_mpt.walk(result["state_root"], result["path"], result["nodes"])
        root = result["state_root"]
        nodes = result["nodes"]
    else:
        slot = result["slots"][0]
        key_source = f'abi.encodePacked(keccak256(hex"{slot["key"].hex()}"))'
        expected = oracle_mpt.walk(result["storage_root"], slot["path"], slot["nodes"])
        root = result["storage_root"]
        nodes = slot["nodes"]
    body = f"""{sol_nodes(nodes)}
    function verify() external pure returns (uint256) {{
        bytes[] memory keys = new bytes[](1);
        keys[0] = {key_source};
        StorageValue[] memory values = EthereumTrie.VerifyProof(
            bytes32(0x{root.hex()}),
            benchProof(),
            keys
        );
        require(values.length == 1, "count");
        require(keccak256(values[0].value) == bytes32(0x{oracle_mpt.keccak256(expected).hex()}), "value");
        return values[0].value.length + 1;
    }}

    function baseline() external pure returns (uint256) {{
        bytes[] memory keys = new bytes[](1);
        keys[0] = {key_source};
        return benchChecksum() + keys[0].length;
    }}
"""
    return vendor + sol_wrapper(body)


def abi_encoded_words(words):
    blob = (32).to_bytes(32, "big") + len(words).to_bytes(32, "big") + b"".join(words)
    return blob.hex()


def render_ssz_fe(name, root, gindex, branch, leaf_consts, verify_body, baseline_body):
    text = concatenate(SSZ_ORDER)
    consts = [
        f"const BENCH_ROOT: u256 = 0x{root.hex()}\n",
        f"const BENCH_GINDEX: u256 = {gindex}\n",
        fe_word_array("BENCH_BRANCH", branch),
        f"const BENCH_DEPTH: usize = {len(branch)}\n",
        leaf_consts,
    ]
    contract = f"""{FE_MSG}
pub contract AssayBench {{
    recv BenchMsg {{{verify_body}{baseline_body}
    }}
}}
"""
    return text + "\n" + "".join(consts) + contract


def render_ssz_sol(root, gindex, branch, extra_body, verify_expr):
    vendor = (VENDOR / "SSZ.sol").read_text()
    body = f"""    function branchWords() internal pure returns (bytes32[] memory words) {{
        words = abi.decode(hex"{abi_encoded_words(branch)}", (bytes32[]));
    }}

    function callVerify(bytes32[] calldata proof, bytes32 root, bytes32 leaf, uint256 gI)
        external
        view
        returns (bool)
    {{
        return SSZ.verifyProof(proof, root, leaf, gI);
    }}

    function callBaseline(bytes32[] calldata proof, bytes32 root, bytes32 leaf, uint256 gI)
        external
        pure
        returns (bool)
    {{
        return (proof.length ^ uint256(root) ^ uint256(leaf) ^ gI) > 0;
    }}
{extra_body}
    function verify() external view returns (uint256) {{
        require(this.callVerify(branchWords(), bytes32(0x{root.hex()}), benchLeaf(), {gindex}), "proof");
        return 1;
    }}

    function baseline() external view returns (uint256) {{
        require(this.callBaseline(branchWords(), bytes32(0x{root.hex()}), benchLeaf(), {gindex}), "baseline");
        return {verify_expr};
    }}
"""
    return vendor + sol_wrapper(body)


def payload_fixture():
    chain = oracle_ssz.analyze(json.loads((FIXTURES / "chain_beacon.json").read_text()), FIXTURES)
    proof = chain["proofs"]["execution_payload.state_root"]
    root = chain["root"]
    leaf = proof["leaf"]
    fe_leaf = f"const BENCH_LEAF: u256 = 0x{leaf.hex()}\n"
    fe_verify = """
        Verify -> u256 {
            let branch: Branch<BENCH_DEPTH> = Branch::new(BENCH_BRANCH)
            match verify_payload_field(
                beacon_root: BeaconRoot::new(BENCH_ROOT),
                which: PayloadField::StateRoot,
                leaf: BENCH_LEAF,
                branch,
            ) {
                Result::Ok(()) => 1,
                Result::Err(_) => core::panic_code(1),
            }
        }
"""
    fe_baseline = """
        Baseline -> u256 {
            let branch: Branch<BENCH_DEPTH> = Branch::new(BENCH_BRANCH)
            BENCH_LEAF ^ BENCH_GINDEX ^ branch.nodes().len() as u256
        }
"""
    fe_text = render_ssz_fe("ssz_payload", root, proof["gindex"], proof["branch"], fe_leaf, fe_verify, fe_baseline)
    sol_extra = f"""
    function benchLeaf() internal pure returns (bytes32) {{
        return bytes32(0x{leaf.hex()});
    }}
"""
    sol_text = render_ssz_sol(root, proof["gindex"], proof["branch"], sol_extra, "2")
    return fe_text, sol_text


def validator_fixture():
    data = oracle_ssz.analyze(json.loads((FIXTURES / "validator_beacon.json").read_text()), FIXTURES)
    proof = data["proofs"][f"validators[{data['index']}]"]
    record = data["record"]
    root = data["root"]
    epochs = {name: record[name] for name in oracle_ssz.VALIDATOR_EPOCHS}
    fe_leaf = "".join(
        [
            fe_word_array("BENCH_PUBKEY_WORDS", words_of(record["pubkey"])),
            f"const BENCH_INDEX: u64 = {data['index']}\n",
            f"const BENCH_CREDENTIALS: u256 = 0x{record['withdrawal_credentials'].hex()}\n",
            f"const BENCH_EFFECTIVE_BALANCE: u64 = {record['effective_balance']}\n",
            f"const BENCH_SLASHED: bool = {'true' if record['slashed'] else 'false'}\n",
        ]
        + [f"const BENCH_{name.upper()}: u64 = {value}\n" for name, value in epochs.items()]
    )
    fe_verify = """
        Verify -> u256 {
            let pubkey = load_packed(BENCH_PUBKEY_WORDS, len: 48)
            let pubkey_root = match bytes48_leaf(pubkey.span()) {
                Result::Ok(root) => root,
                Result::Err(_) => core::panic_code(1),
            }
            let record = Validator {
                pubkey_root,
                withdrawal_credentials: BENCH_CREDENTIALS,
                effective_balance: BENCH_EFFECTIVE_BALANCE,
                slashed: BENCH_SLASHED,
                activation_eligibility_epoch: BENCH_ACTIVATION_ELIGIBILITY_EPOCH,
                activation_epoch: BENCH_ACTIVATION_EPOCH,
                exit_epoch: BENCH_EXIT_EPOCH,
                withdrawable_epoch: BENCH_WITHDRAWABLE_EPOCH,
            }
            let branch: Branch<BENCH_DEPTH> = Branch::new(BENCH_BRANCH)
            match verify_validator(
                beacon_root: BeaconRoot::new(BENCH_ROOT),
                index: BENCH_INDEX,
                validator: record,
                branch,
            ) {
                Result::Ok(()) => 1,
                Result::Err(_) => core::panic_code(1),
            }
        }
"""
    fe_baseline = """
        Baseline -> u256 {
            let pubkey = load_packed(BENCH_PUBKEY_WORDS, len: 48)
            let pubkey_root = match bytes48_leaf(pubkey.span()) {
                Result::Ok(root) => root,
                Result::Err(_) => core::panic_code(1),
            }
            let record = Validator {
                pubkey_root,
                withdrawal_credentials: BENCH_CREDENTIALS,
                effective_balance: BENCH_EFFECTIVE_BALANCE,
                slashed: BENCH_SLASHED,
                activation_eligibility_epoch: BENCH_ACTIVATION_ELIGIBILITY_EPOCH,
                activation_epoch: BENCH_ACTIVATION_EPOCH,
                exit_epoch: BENCH_EXIT_EPOCH,
                withdrawable_epoch: BENCH_WITHDRAWABLE_EPOCH,
            }
            let branch: Branch<BENCH_DEPTH> = Branch::new(BENCH_BRANCH)
            record.root() ^ BENCH_GINDEX ^ branch.nodes().len() as u256
        }
"""
    fe_text = render_ssz_fe("ssz_validator", root, proof["gindex"], proof["branch"], fe_leaf, fe_verify, fe_baseline)
    sol_extra = f"""
    function benchLeaf() internal view returns (bytes32) {{
        SSZ.Validator memory validator = SSZ.Validator({{
            pubkey: hex"{record['pubkey'].hex()}",
            withdrawalCredentials: bytes32(0x{record['withdrawal_credentials'].hex()}),
            effectiveBalance: {record['effective_balance']},
            slashed: {'true' if record['slashed'] else 'false'},
            activationEligibilityEpoch: {epochs['activation_eligibility_epoch']},
            activationEpoch: {epochs['activation_epoch']},
            exitEpoch: {epochs['exit_epoch']},
            withdrawableEpoch: {epochs['withdrawable_epoch']}
        }});
        return SSZ.validatorHashTreeRoot(validator);
    }}
"""
    sol_text = render_ssz_sol(root, proof["gindex"], proof["branch"], sol_extra, "2")
    return fe_text, sol_text


MANIFEST = 'contract = "AssayBench"\n\n[[calls]]\nfunction = "verify()"\n\n[[calls]]\nfunction = "baseline()"\n'


def expected_files():
    check_vendor()
    usdc = oracle_mpt.analyze(json.loads((FIXTURES / "chain_storage_usdc.json").read_text()))
    weth = oracle_mpt.analyze(json.loads((FIXTURES / "chain_storage_weth.json").read_text()))
    payload_fe, payload_sol = payload_fixture()
    validator_fe, validator_sol = validator_fixture()
    files = {}
    for name, fe_text, sol_text in (
        ("mpt_account", render_trie_fe("account", usdc), render_trie_sol("account", usdc)),
        ("mpt_storage", render_trie_fe("storage", weth), render_trie_sol("storage", weth)),
        ("ssz_payload", payload_fe, payload_sol),
        ("ssz_validator", validator_fe, validator_sol),
    ):
        files[BENCH / f"{name}.fe"] = fe_text
        files[BENCH / f"{name}.sol"] = sol_text
        files[BENCH / f"{name}.toml"] = MANIFEST
    return files


def fe_check(path, text):
    fe_binary = os.environ.get("FE")
    if not fe_binary:
        raise SystemExit("error: set FE to the compiler binary before generating")
    with tempfile.TemporaryDirectory() as scratch:
        ingot = pathlib.Path(scratch)
        (ingot / "src").mkdir()
        (ingot / "fe.toml").write_text('[ingot]\nname = "bench_fixture"\nversion = "0.1.0"\n')
        (ingot / "src" / "lib.fe").write_text(text)
        done = subprocess.run([fe_binary, "check"], cwd=ingot, capture_output=True, text=True)
        if done.returncode != 0:
            raise SystemExit(f"error: {path.name} does not pass fe check:\n{done.stdout}{done.stderr}")


def generate():
    files = expected_files()
    for path, text in sorted(files.items()):
        if path.suffix == ".fe":
            fe_check(path, text)
    BENCH.mkdir(parents=True, exist_ok=True)
    for path, text in sorted(files.items()):
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")


def check():
    files = expected_files()
    problems = 0
    for path, text in sorted(files.items()):
        if not path.exists():
            print(f"missing {path.relative_to(ROOT)}")
            problems += 1
        elif path.read_text() != text:
            print(f"stale {path.relative_to(ROOT)}")
            problems += 1
    for stray in sorted(BENCH.iterdir()):
        if stray.is_file() and stray not in files:
            print(f"unexpected {stray.relative_to(ROOT)}")
            problems += 1
    if problems:
        raise SystemExit(1)
    print(f"{len(files)} bench files match src and fixtures")


def main(argv):
    if len(argv) != 2 or argv[1] not in ("generate", "check"):
        raise SystemExit(__doc__)
    if argv[1] == "generate":
        generate()
    else:
        check()


if __name__ == "__main__":
    main(sys.argv)
