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
import oracle_ssz

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
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
        names = CHAIN_PROOFS
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
            elif kind == oracle_mpt.SYNTHETIC_KIND:
                text = render_synthetic(fixture)
            else:
                raise ValueError(f"unknown fixture kind {kind!r}")
        except (oracle_mpt.ProofError, oracle_ssz.CheckError, KeyError, TypeError, ValueError) as e:
            raise SystemExit(f"error: {path.name}: {type(e).__name__}: {e}")
        files[OUT_DIR / f"{name}.fe"] = text
        names.append(name)
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
