"""Turn fixtures/*.json into Fe constant modules under src/fixtures/.

usage: gen_fixtures.py generate
       gen_fixtures.py check

generate runs the oracle on every fixture, refuses to continue if any fails,
and writes one src/fixtures/<name>.fe per fixture plus src/fixtures.fe, which
re-exports the modules. Arrays follow fe fmt's layout: one line when it fits
in 100 columns, otherwise one element per line. Account and storage values in the generated constants
are the oracle's decoded results, not the RPC's claims; the oracle has already
checked that both agree.

check regenerates everything in memory and exits nonzero if any file on disk
differs, so CI can prove the committed constants match the committed JSON.

Layout of a generated module: proof nodes are concatenated into one byte
array, and an offsets array marks where each node starts, with one extra
entry equal to the total length. Storage proofs for every slot are
concatenated the same way, and SLOT_NODE_STARTS gives, per slot, the index
into SLOT_OFFSETS where that slot's nodes begin, again with one extra entry,
and SLOT_NODE_COUNTS gives the number of nodes per slot.
ACCOUNT_PATH and SLOT_PATHS are the keccak hashed trie keys the oracle walked.
The oracle also verifies that the header hashes to BLOCK_HASH before any
constant is written, so the state root is bound to the block.

Beacon fixtures (kind beacon_chain or beacon_validator) are checked by
oracle_ssz.py first. Their modules hold the beacon header fields, BLOCK_ROOT,
and for every proven field a <FIELD>_GINDEX, <FIELD>_LEAF, <FIELD>_DEPTH and
<FIELD>_BRANCH, the branch ordered from the leaf's sibling up to the root's
child. A leaf or sibling is the 32-byte chunk read as a big-endian word.
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


def word(data):
    return "0x" + data.hex()


MAX_WIDTH = 100


def array(name, type_name, items):
    single = f"pub const {name}: [{type_name}; {len(items)}] = [{', '.join(items)}]\n"
    if len(single) - 1 <= MAX_WIDTH:
        return single
    body = "\n".join(f"    {item}," for item in items)
    return f"pub const {name}: [{type_name}; {len(items)}] = [\n{body}\n]\n"


def byte_array(name, data):
    return array(name, "u8", [f"0x{b:02x}" for b in data])


def usize_array(name, values):
    return array(name, "usize", [str(v) for v in values])


def word_array(name, values):
    return array(name, "u256", values)


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


def render(fixture):
    result = oracle_mpt.analyze(fixture)
    header = fixture["header"]
    account_bytes, account_offsets, _ = concatenate([result["nodes"]])
    slot_bytes, slot_offsets, slot_starts = concatenate([s["nodes"] for s in result["slots"]])
    parts = [
        f"pub const CHAIN_ID: u64 = {fixture['chainId']}\n",
        f"pub const BLOCK_NUMBER: u64 = {int(header['number'], 16)}\n",
        f"pub const BLOCK_HASH: u256 = {header['hash']}\n",
        f"pub const BLOCK_TIMESTAMP: u64 = {int(header['timestamp'], 16)}\n",
        f"pub const STATE_ROOT: u256 = {word(result['state_root'])}\n",
        f"pub const ADDRESS: u256 = {word(result['address'])}\n",
        byte_array("ADDRESS_BYTES", result["address"]),
        f"pub const ACCOUNT_PATH: u256 = {word(result['path'])}\n",
        f"pub const ACCOUNT_PRESENT: bool = {'true' if result['present'] else 'false'}\n",
        f"pub const NONCE: u64 = {result['nonce']}\n",
        f"pub const BALANCE: u256 = {result['balance']}\n",
        f"pub const STORAGE_ROOT: u256 = {word(result['storage_root'])}\n",
        f"pub const CODE_HASH: u256 = {word(result['code_hash'])}\n",
        f"pub const ACCOUNT_NODE_COUNT: usize = {len(result['nodes'])}\n",
        f"pub const ACCOUNT_INLINE: bool = {'true' if result['inline'] else 'false'}\n",
        usize_array("ACCOUNT_OFFSETS", account_offsets),
        byte_array("ACCOUNT_BYTES", account_bytes),
        f"pub const SLOT_COUNT: usize = {len(result['slots'])}\n",
        word_array("SLOT_KEYS", [word(s["key"]) for s in result["slots"]]),
        word_array("SLOT_PATHS", [word(s["path"]) for s in result["slots"]]),
        bool_array("SLOT_INLINE", [s["inline"] for s in result["slots"]]),
        bool_array("SLOT_PRESENT", [s["present"] for s in result["slots"]]),
        word_array("SLOT_VALUES", [str(s["value"]) for s in result["slots"]]),
        usize_array("SLOT_NODE_STARTS", slot_starts),
        usize_array("SLOT_NODE_COUNTS", [len(s["nodes"]) for s in result["slots"]]),
        usize_array("SLOT_OFFSETS", slot_offsets),
        byte_array("SLOT_BYTES", slot_bytes),
    ]
    return "".join(parts)


BEACON_FIELD_NAMES = {
    "execution_payload.state_root": "PAYLOAD_STATE_ROOT",
    "execution_payload.block_number": "PAYLOAD_BLOCK_NUMBER",
    "execution_payload.block_hash": "PAYLOAD_BLOCK_HASH",
    "withdrawal_credentials": "WITHDRAWAL_CREDENTIALS",
    "effective_balance": "EFFECTIVE_BALANCE",
}


def proof_constants(proof, prefix):
    branch = proof["branch"]
    return [
        f"pub const {prefix}_GINDEX: u256 = {int(proof['gindex'])}\n",
        f"pub const {prefix}_LEAF: u256 = {proof['leaf']}\n",
        f"pub const {prefix}_DEPTH: usize = {len(branch)}\n",
        word_array(f"{prefix}_BRANCH", branch),
    ]


def render_beacon(fixture):
    oracle_ssz.check_fixture(fixture)
    beacon = fixture["beacon"]
    header = beacon["header"]
    parts = [
        f"pub const BLOCK_ROOT: u256 = {beacon['blockRoot']}\n",
        f"pub const SLOT: u64 = {int(header['slot'])}\n",
        f"pub const PROPOSER_INDEX: u64 = {int(header['proposer_index'])}\n",
        f"pub const PARENT_ROOT: u256 = {header['parent_root']}\n",
        f"pub const HEADER_STATE_ROOT: u256 = {header['state_root']}\n",
        f"pub const BODY_ROOT: u256 = {header['body_root']}\n",
    ]
    if fixture["kind"] == "beacon_chain":
        execution = fixture["execution"]
        parts += [
            f"pub const EXEC_BLOCK_NUMBER: u64 = {int(execution['header']['number'], 16)}\n",
            f"pub const EXEC_BLOCK_HASH: u256 = {execution['header']['hash']}\n",
            f"pub const EXEC_STATE_ROOT: u256 = {execution['header']['stateRoot']}\n",
            f"pub const CHILD_BLOCK_NUMBER: u64 = {int(execution['childHeader']['number'], 16)}\n",
            f"pub const CHILD_TIMESTAMP: u64 = {int(execution['childHeader']['timestamp'], 16)}\n",
        ]
        prefix_of = lambda field: BEACON_FIELD_NAMES[field]
    else:
        index = int(fixture["validatorIndex"])
        validator = fixture["validator"]
        parts += [
            f"pub const VALIDATOR_INDEX: u64 = {index}\n",
            f"pub const WITHDRAWAL_CREDENTIALS: u256 = {validator['withdrawal_credentials']}\n",
            f"pub const EFFECTIVE_BALANCE: u64 = {int(validator['effective_balance'])}\n",
        ]
        prefix_of = lambda field: BEACON_FIELD_NAMES[field.removeprefix(f"validators[{index}].")]
    for proof in sorted(fixture["proofs"], key=lambda p: p["field"]):
        parts += proof_constants(proof, prefix_of(proof["field"]))
    return "".join(parts)


def expected_files():
    files = {}
    names = []
    for path in sorted(FIXTURES.glob("*.json")):
        fixture = json.loads(path.read_text())
        name = fixture["name"]
        if name != path.stem:
            raise SystemExit(f"error: {path} holds fixture named {name}")
        if not name.isidentifier() or not name.islower():
            raise SystemExit(f"error: {name} is not a lowercase Fe module name")
        if fixture.get("kind") in ("beacon_chain", "beacon_validator"):
            files[OUT_DIR / f"{name}.fe"] = render_beacon(fixture)
        else:
            files[OUT_DIR / f"{name}.fe"] = render(fixture)
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
    try:
        if argv[1] == "generate":
            generate()
        else:
            check()
    except (oracle_mpt.ProofError, oracle_ssz.CheckError) as e:
        raise SystemExit(f"error: oracle rejected a fixture: {e}")


if __name__ == "__main__":
    main(sys.argv)
