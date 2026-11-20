"""Turn fixtures/*.json into Fe constant modules under src/fixtures/.

usage: gen_fixtures.py generate
       gen_fixtures.py check

generate runs the matching oracle on every fixture, refuses to continue if any
fails, and writes one src/fixtures/<name>.fe per fixture plus src/fixtures.fe,
which re-exports the modules. Every constant is rendered from the oracle's
parsed values, never copied from the JSON text. Arrays follow fe fmt's layout:
one line when it fits in 100 columns, otherwise one element per line.

check regenerates everything in memory and exits nonzero if any file on disk
differs, so CI can prove the committed constants match the committed JSON.

Trie fixtures (kind account or storage): proof nodes are concatenated into one
byte array, and an offsets array marks where each node starts, with one extra
entry equal to the total length. Storage proofs for every slot are
concatenated the same way; SLOT_NODE_STARTS gives, per slot, the index into
SLOT_OFFSETS where that slot's nodes begin, with one extra entry for the end.
Values are the oracle's decoded results. Every constant is pub(ingot): tests in
this ingot read them, and a dependent ingot cannot.

Beacon fixtures (kind beacon_chain or beacon_validator): the five header
fields, BLOCK_ROOT, CHILD_TIMESTAMP (the EIP-4788 key), and for every proven
field <FIELD>_GINDEX, <FIELD>_LEAF and <FIELD>_BRANCH, the branch ordered from
the leaf's sibling up to the root's child. A leaf or sibling is the 32-byte
chunk read as a big-endian word. Validator modules also hold the validator's
index and all eight fields of its record, from which a test can rebuild the
record's root and the pubkey and balance leaves.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt
import oracle_receipt
import oracle_ssz

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
CONSENSUS_SPEC = FIXTURES / "consensus_spec"
SPEC_CASES = 5
OUT_DIR = ROOT / "src" / "fixtures"
INDEX = ROOT / "src" / "fixtures.fe"
MAX_WIDTH = 100


def word(data):
    if len(data) != 32:
        raise ValueError(f"word of {len(data)} bytes")
    return "0x" + data.hex()


def const(name, type_name, value):
    return f"pub(ingot) const {name}: {type_name} = {value}\n"


def array(name, type_name, items):
    single = f"pub(ingot) const {name}: [{type_name}; {len(items)}] = [{', '.join(items)}]\n"
    if len(single) - 1 <= MAX_WIDTH:
        return single
    body = "\n".join(f"    {item}," for item in items)
    return f"pub(ingot) const {name}: [{type_name}; {len(items)}] = [\n{body}\n]\n"


def byte_array(name, data):
    return array(name, "u8", [f"0x{b:02x}" for b in data])


def usize_array(name, values):
    return array(name, "usize", [str(v) for v in values])


def word_array(name, values):
    return array(name, "u256", [word(v) for v in values])


def packed_bytes(name, data):
    padded = bytes(data) + bytes(-len(data) % 32)
    words = [padded[i : i + 32] for i in range(0, len(padded), 32)]
    return const(f"{name}_LEN", "usize", len(data)) + word_array(f"{name}_WORDS", words)


def bool_array(name, values):
    return array(name, "bool", ["true" if v else "false" for v in values])


def concatenate(node_lists):
    flat = bytearray()
    offsets = [0]
    starts = [0]
    for nodes in node_lists:
        for node in nodes:
            flat.extend(node)
            offsets.append(len(flat))
        starts.append(len(offsets) - 1)
    return bytes(flat), offsets, starts


def render_trie(fixture):
    result = oracle_mpt.analyze(fixture)
    account_bytes, account_offsets, _ = concatenate([result["nodes"]])
    slot_bytes, slot_offsets, slot_starts = concatenate([s["nodes"] for s in result["slots"]])
    parts = [
        const("STATE_ROOT", "u256", word(result["state_root"])),
        byte_array("ADDRESS_BYTES", result["address"]),
        const("ACCOUNT_PRESENT", "bool", "true" if result["present"] else "false"),
        const("NONCE", "u64", result["nonce"]),
        const("BALANCE", "u256", result["balance"]),
        const("STORAGE_ROOT", "u256", word(result["storage_root"])),
        const("CODE_HASH", "u256", word(result["code_hash"])),
        const("ACCOUNT_NODE_COUNT", "usize", len(result["nodes"])),
        usize_array("ACCOUNT_OFFSETS", account_offsets),
        byte_array("ACCOUNT_BYTES", account_bytes),
        word_array("SLOT_KEYS", [s["key"] for s in result["slots"]]),
        bool_array("SLOT_PRESENT", [s["present"] for s in result["slots"]]),
        array("SLOT_VALUES", "u256", [str(s["value"]) for s in result["slots"]]),
        usize_array("SLOT_NODE_STARTS", slot_starts),
        usize_array("SLOT_OFFSETS", slot_offsets),
        byte_array("SLOT_BYTES", slot_bytes),
    ]
    return "".join(parts)


CHAIN_PROOFS = {
    "execution_payload.state_root": "PAYLOAD_STATE_ROOT",
    "execution_payload.block_number": "PAYLOAD_BLOCK_NUMBER",
    "execution_payload.block_hash": "PAYLOAD_BLOCK_HASH",
}
VALIDATOR_PROOFS = {
    "pubkey": "VALIDATOR_PUBKEY",
    "withdrawal_credentials": "VALIDATOR_WITHDRAWAL_CREDENTIALS",
    "effective_balance": "VALIDATOR_EFFECTIVE_BALANCE",
}
STATE_PROOFS = {
    "genesis_validators_root": "GENESIS_VALIDATORS_ROOT",
    "fork.current_version": "FORK_VERSION",
    "latest_execution_payload_header.block_hash": "LATEST_BLOCK_HASH",
}


def proof_constants(prefix, proof):
    return [
        const(f"{prefix}_GINDEX", "u256", proof["gindex"]),
        const(f"{prefix}_LEAF", "u256", word(proof["leaf"])),
        word_array(f"{prefix}_BRANCH", proof["branch"]),
    ]


def render_beacon(fixture):
    result = oracle_ssz.analyze(fixture, FIXTURES)
    header = result["header"]
    parts = [
        const("BLOCK_ROOT", "u256", word(result["root"])),
        const("SLOT", "u64", header["slot"]),
        const("PROPOSER_INDEX", "u64", header["proposer_index"]),
        const("PARENT_ROOT", "u256", word(header["parent_root"])),
        const("HEADER_STATE_ROOT", "u256", word(header["state_root"])),
        const("BODY_ROOT", "u256", word(header["body_root"])),
        const("CHILD_TIMESTAMP", "u64", result["execution"]["child_timestamp"]),
    ]
    proofs = result["proofs"]
    if result["kind"] == "beacon_chain":
        names = dict(CHAIN_PROOFS)
        if "execution_payload.receipts_root" in proofs:
            names["execution_payload.receipts_root"] = "PAYLOAD_RECEIPTS_ROOT"
    elif result["kind"] == "beacon_history":
        parts += [
            const("TARGET_SLOT", "u64", result["target"]),
            const("HISTORICAL_ROOT", "u256", word(result["historical_root"])),
        ]
        names = {f"block_roots[{result['position']}]": "BLOCK_ROOTS_ELEMENT"}
        names.update(STATE_PROOFS)
    elif result["kind"] == "beacon_deephistory":
        parts += [
            const("TARGET_SLOT", "u64", result["target"]),
            const("HISTORICAL_ROOT", "u256", word(result["historical_root"])),
            const("SUMMARY_INDEX", "u64", result["summary_index"]),
            const("SUMMARY_ROOT", "u256", word(result["summary_root"])),
        ]
        names = {
            f"historical_summaries[{result['summary_index']}].block_summary_root": "SUMMARY_BLOCK_ROOT",
            f"block_summary[{result['position']}]": "BLOCK_SUMMARY_ELEMENT",
        }
        names.update(STATE_PROOFS)
    else:
        record = result["record"]
        parts += [
            const("VALIDATOR_INDEX", "u64", result["index"]),
            byte_array("PUBKEY", result["pubkey"]),
            const("WITHDRAWAL_CREDENTIALS", "u256", word(record["withdrawal_credentials"])),
            const("EFFECTIVE_BALANCE", "u64", result["balance"]),
            const("SLASHED", "bool", "true" if record["slashed"] else "false"),
        ]
        parts += [const(name.upper(), "u64", record[name]) for name in oracle_ssz.VALIDATOR_EPOCHS]
        names = {result["prefix"] + field: name for field, name in VALIDATOR_PROOFS.items()}
        names[result["prefix"][:-1]] = "VALIDATOR"
        names.update(STATE_PROOFS)
    if set(names) != set(proofs):
        raise ValueError(f"proof fields {sorted(proofs)} differ from {sorted(names)}")
    for field in sorted(names):
        parts += proof_constants(names[field], proofs[field])
    if result["kind"] == "beacon_chain" and "payloadMultiproof" in fixture:
        helpers = [int(h, 16) for h in fixture["payloadMultiproof"]["helpers"]]
        parts.append(array("PAYLOAD_MULTIPROOF", "u256", [str(h) for h in helpers]))
    return "".join(parts)


def render_synthetic(fixture):
    tries = oracle_mpt.analyze_synthetic(fixture)
    roots, node_offsets, node_bytes = [], [0], bytearray()
    case_trie, keys, present, value_offsets, value_bytes = [], [], [], [0], bytearray()
    proof_starts, proof_nodes = [0], []
    for t, trie in enumerate(tries):
        roots.append(trie["root"])
        first = len(node_offsets) - 1
        for node in trie["nodes"]:
            node_bytes.extend(node)
            node_offsets.append(len(node_bytes))
        for case in trie["cases"]:
            case_trie.append(t)
            keys.append(case["key"])
            present.append(case["value"] is not None)
            value_bytes.extend(case["value"] or b"")
            value_offsets.append(len(value_bytes))
            proof_nodes.extend(first + i for i in case["proof"])
            proof_starts.append(len(proof_nodes))
    parts = [
        const("TRIE_COUNT", "usize", len(tries)),
        const("CASE_COUNT", "usize", len(keys)),
        word_array("ROOTS", roots),
        usize_array("CASE_TRIE", case_trie),
        word_array("CASE_KEYS", keys),
        bool_array("CASE_PRESENT", present),
        usize_array("VALUE_OFFSETS", value_offsets),
        packed_bytes("VALUE_BYTES", value_bytes),
        usize_array("PROOF_STARTS", proof_starts),
        usize_array("PROOF_NODES", proof_nodes),
        usize_array("NODE_OFFSETS", node_offsets),
        packed_bytes("NODE_BYTES", node_bytes),
    ]
    return "".join(parts)


def yaml_scalars(path):
    values = {}
    for line in path.read_text().splitlines():
        key, separator, raw = line.partition(": ")
        if not separator or not key.isidentifier() or key in values:
            raise SystemExit(f"error: {path}: unexpected line {line!r}")
        raw = raw.strip()
        if raw.startswith("'0x") and raw.endswith("'"):
            values[key] = oracle_mpt.hex_bytes(raw[1:-1])
        elif raw in ("true", "false"):
            values[key] = raw == "true"
        elif raw.isdigit() and (raw == "0" or not raw.startswith("0")):
            number = int(raw)
            if number >> 64:
                raise SystemExit(f"error: {path}: {key} does not fit uint64")
            values[key] = number
        else:
            raise SystemExit(f"error: {path}: unexpected value {raw!r}")
    return values


def spec_case(container, index, keys):
    directory = CONSENSUS_SPEC / container / f"case_{index}"
    values = yaml_scalars(directory / "value.yaml")
    if set(values) != set(keys):
        raise SystemExit(f"error: {directory}: fields {sorted(values)} differ from {sorted(keys)}")
    roots = yaml_scalars(directory / "roots.yaml")
    if set(roots) != {"root"} or len(roots["root"]) != 32:
        raise SystemExit(f"error: {directory}: roots.yaml must hold one 32-byte root")
    return values, roots["root"]


VALIDATOR_KEYS = ("pubkey", "withdrawal_credentials", "effective_balance", "slashed") + oracle_ssz.VALIDATOR_EPOCHS
HEADER_KEYS = ("slot", "proposer_index", "parent_root", "state_root", "body_root")


def render_spec_vectors():
    columns = {name: [] for name in ("pubkey_a", "pubkey_b", "credentials", "balance", "slashed", "eligibility", "activation", "exit", "withdrawable", "validator_root", "slot", "proposer", "parent", "state", "body", "header_root")}
    for index in range(SPEC_CASES):
        values, root = spec_case("Validator", index, VALIDATOR_KEYS)
        if len(values["pubkey"]) != 48 or len(values["withdrawal_credentials"]) != 32:
            raise SystemExit(f"error: Validator case_{index}: wrong byte lengths")
        parsed = oracle_ssz.parse_validator(
            {
                "pubkey": "0x" + values["pubkey"].hex(),
                "withdrawal_credentials": "0x" + values["withdrawal_credentials"].hex(),
                "effective_balance": str(values["effective_balance"]),
                "slashed": values["slashed"],
                **{name: str(values[name]) for name in oracle_ssz.VALIDATOR_EPOCHS},
            }
        )
        if oracle_ssz.validator_root(parsed) != root:
            raise SystemExit(f"error: Validator case_{index}: the oracle disagrees with the spec root")
        padded = values["pubkey"] + bytes(16)
        columns["pubkey_a"].append(padded[0:32])
        columns["pubkey_b"].append(padded[32:64])
        columns["credentials"].append(values["withdrawal_credentials"])
        columns["balance"].append(values["effective_balance"])
        columns["slashed"].append(values["slashed"])
        columns["eligibility"].append(values["activation_eligibility_epoch"])
        columns["activation"].append(values["activation_epoch"])
        columns["exit"].append(values["exit_epoch"])
        columns["withdrawable"].append(values["withdrawable_epoch"])
        columns["validator_root"].append(root)
        header_values, header_root_bytes = spec_case("BeaconBlockHeader", index, HEADER_KEYS)
        parsed_header = oracle_ssz.parse_header(
            {
                "slot": str(header_values["slot"]),
                "proposer_index": str(header_values["proposer_index"]),
                "parent_root": "0x" + header_values["parent_root"].hex(),
                "state_root": "0x" + header_values["state_root"].hex(),
                "body_root": "0x" + header_values["body_root"].hex(),
            }
        )
        if oracle_ssz.header_root(parsed_header) != header_root_bytes:
            raise SystemExit(f"error: BeaconBlockHeader case_{index}: the oracle disagrees with the spec root")
        columns["slot"].append(header_values["slot"])
        columns["proposer"].append(header_values["proposer_index"])
        columns["parent"].append(header_values["parent_root"])
        columns["state"].append(header_values["state_root"])
        columns["body"].append(header_values["body_root"])
        columns["header_root"].append(header_root_bytes)
    def u64_array(name, values):
        return array(name, "u64", [str(v) for v in values])
    parts = [
        const("SPEC_CASES", "usize", SPEC_CASES),
        word_array("SPEC_VALIDATOR_PUBKEY_A", columns["pubkey_a"]),
        word_array("SPEC_VALIDATOR_PUBKEY_B", columns["pubkey_b"]),
        word_array("SPEC_VALIDATOR_CREDENTIALS", columns["credentials"]),
        u64_array("SPEC_VALIDATOR_BALANCE", columns["balance"]),
        bool_array("SPEC_VALIDATOR_SLASHED", columns["slashed"]),
        u64_array("SPEC_VALIDATOR_ELIGIBILITY", columns["eligibility"]),
        u64_array("SPEC_VALIDATOR_ACTIVATION", columns["activation"]),
        u64_array("SPEC_VALIDATOR_EXIT", columns["exit"]),
        u64_array("SPEC_VALIDATOR_WITHDRAWABLE", columns["withdrawable"]),
        word_array("SPEC_VALIDATOR_ROOT", columns["validator_root"]),
        u64_array("SPEC_HEADER_SLOT", columns["slot"]),
        u64_array("SPEC_HEADER_PROPOSER", columns["proposer"]),
        word_array("SPEC_HEADER_PARENT", columns["parent"]),
        word_array("SPEC_HEADER_STATE", columns["state"]),
        word_array("SPEC_HEADER_BODY", columns["body"]),
        word_array("SPEC_HEADER_ROOT", columns["header_root"]),
    ]
    return "".join(parts)


def render_receipt(fixture):
    result = oracle_receipt.analyze(fixture)
    node_bytes, node_offsets, _ = concatenate([result["nodes"]])
    parts = [
        const("RECEIPTS_ROOT", "u256", word(result["receipts_root"])),
        const("TX_INDEX", "u64", result["index"]),
        const("PRESENT", "bool", "true" if result["present"] else "false"),
        const("NODE_COUNT", "usize", len(result["nodes"])),
        usize_array("NODE_OFFSETS", node_offsets),
        byte_array("NODE_BYTES", node_bytes),
    ]
    if result["present"]:
        receipt = result["receipt"]
        parts += [
            const("SUCCEEDED", "bool", "true" if receipt["succeeded"] else "false"),
            const("CUMULATIVE_GAS", "u64", receipt["cumulative_gas"]),
            const("TX_TYPE", "u8", receipt["tx_type"]),
            const("LOG_COUNT", "usize", len(receipt["logs"])),
        ]
        if "log_index" in result:
            log = receipt["logs"][result["log_index"]]
            topics = [int.from_bytes(t, "big") for t in log["topics"]]
            topics += [0] * (4 - len(log["topics"]))
            parts += [
                const("LOG_INDEX", "usize", result["log_index"]),
                const("LOG_ADDRESS", "u256", int.from_bytes(log["address"], "big")),
                const("LOG_TOPIC_COUNT", "usize", len(log["topics"])),
                array("LOG_TOPICS", "u256", [str(t) for t in topics]),
                const("LOG_DATA_HASH", "u256", int.from_bytes(oracle_mpt.keccak256(log["data"]), "big")),
                const("LOG_DATA_LEN", "usize", len(log["data"])),
            ]
    return "".join(parts)


PQ_PROOF_NAMES = {
    "pubkey": "PUBKEY",
    "vrf_root": "VRF_ROOT",
    "record": "RECORD",
    "genesis_validators_root": "GENESIS",
}


def render_pq(fixture):
    root = bytes.fromhex(fixture["stateRoot"][2:])
    index = int(fixture["validatorIndex"])
    validator = fixture["validator"]
    parts = [
        const("STATE_ROOT", "u256", int(fixture["stateRoot"], 16)),
        const("VALIDATOR_INDEX", "u64", index),
        const("PUBKEY", "u256", int(validator["pubkey"], 16)),
        const("VRF_ROOT", "u256", int(validator["vrf_root"], 16)),
        const("RECORD_EFFECTIVE_BALANCE", "u64", int(validator["effective_balance"])),
        const("RECORD_WITHDRAWAL_CREDENTIALS", "u256", int(validator["withdrawal_credentials"], 16)),
        const("RECORD_SLASHED", "bool", "true" if validator["slashed"] else "false"),
        const("RECORD_ACTIVATION_ELIGIBILITY_EPOCH", "u64", int(validator["activation_eligibility_epoch"])),
        const("RECORD_ACTIVATION_EPOCH", "u64", int(validator["activation_epoch"])),
        const("RECORD_EXIT_EPOCH", "u64", int(validator["exit_epoch"])),
        const("RECORD_WITHDRAWABLE_EPOCH", "u64", int(validator["withdrawable_epoch"])),
    ]
    expected_fields = {
        f"validators[{index}].pubkey": "pubkey",
        f"validators[{index}].vrf_root": "vrf_root",
        f"validators[{index}]": "record",
        "genesis_validators_root": "genesis_validators_root",
    }
    seen = set()
    for proof in fixture["proofs"]:
        field = proof["field"]
        if field not in expected_fields:
            raise ValueError(f"unexpected pq proof {field}")
        short = expected_fields[field]
        seen.add(short)
        leaf = bytes.fromhex(proof["leaf"][2:])
        branch = [bytes.fromhex(n[2:]) for n in proof["branch"]]
        if oracle_ssz.walk(leaf, int(proof["gindex"]), branch) != root:
            raise ValueError(f"pq proof {field} does not reconstruct the state root")
        prefix = PQ_PROOF_NAMES[short]
        parts += [
            const(f"{prefix}_GINDEX", "u256", int(proof["gindex"])),
            const(f"{prefix}_LEAF", "u256", int(proof["leaf"], 16)),
            word_array(f"{prefix}_BRANCH", branch),
        ]
    if seen != set(PQ_PROOF_NAMES):
        raise ValueError(f"pq fixture is missing proofs: {sorted(set(PQ_PROOF_NAMES) - seen)}")
    return "".join(parts)


def expected_files():
    files = {}
    names = []
    for path in sorted(FIXTURES.glob("*.json")):
        try:
            fixture = json.loads(path.read_text())
            name = fixture["name"]
            if name != path.stem:
                raise ValueError(f"holds fixture named {name}")
            if not name.isidentifier() or not name.islower():
                raise ValueError(f"{name} is not a lowercase Fe module name")
            kind = fixture.get("kind")
            if kind in oracle_mpt.MPT_KINDS:
                text = render_trie(fixture)
            elif kind in oracle_ssz.BEACON_KINDS:
                text = render_beacon(fixture)
            elif kind == "receipt":
                text = render_receipt(fixture)
            elif kind == "pq_state":
                text = render_pq(fixture)
            elif kind == oracle_mpt.SYNTHETIC_KIND:
                text = render_synthetic(fixture)
            else:
                raise ValueError(f"unknown fixture kind {kind!r}")
        except (oracle_mpt.ProofError, oracle_ssz.CheckError, oracle_receipt.ReceiptError, KeyError, TypeError, ValueError) as e:
            raise SystemExit(f"error: {path.name}: {type(e).__name__}: {e}")
        files[OUT_DIR / f"{name}.fe"] = text
        names.append(name)
    files[OUT_DIR / "spec_vectors.fe"] = render_spec_vectors()
    names.append("spec_vectors")
    files[INDEX] = "".join(f"pub use {name}::{{self}}\n" for name in names)
    return files


def generate():
    files = expected_files()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for stale in OUT_DIR.glob("*.fe"):
        if stale not in files:
            stale.unlink()
            print(f"removed {stale.relative_to(ROOT)}")
    for path, text in files.items():
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")


def check():
    files = expected_files()
    problems = 0
    for path, text in files.items():
        if not path.exists():
            print(f"missing {path.relative_to(ROOT)}")
            problems += 1
        elif path.read_text() != text:
            print(f"stale {path.relative_to(ROOT)}")
            problems += 1
    for extra in OUT_DIR.glob("*.fe"):
        if extra not in files:
            print(f"unexpected {extra.relative_to(ROOT)}")
            problems += 1
    if problems:
        raise SystemExit(1)
    print(f"{len(files)} generated files match the fixtures")


def main(argv):
    if len(argv) != 2 or argv[1] not in ("generate", "check"):
        raise SystemExit(__doc__)
    if argv[1] == "generate":
        generate()
    else:
        check()


if __name__ == "__main__":
    main(sys.argv)
