"""Independent SSZ checker for beacon fixtures.

usage: oracle_ssz.py <fixture.json> [...]

Uses hashlib SHA-256 only and shares no code with remerkleable. For each
beacon fixture it recomputes the beacon block root from the five header
fields, derives every generalized index from the container field counts,
walks every branch from its leaf to the block root, and checks:

- every value is canonical 0x hex and every object has exactly the expected keys;
- each proven field appears once, under its exact name;
- the execution block that carries the beacon block's payload has the slot's
  timestamp, and its child names the beacon block root as
  parentBeaconBlockRoot, which is what the EIP-4788 contract returns for the
  child's timestamp;
- chain fixtures: the payload's state_root, block_number and block_hash equal
  that execution block, and the trie fixtures listed in mptFixtures exist next
  to it, pass oracle_mpt.py, and were captured at that same block;
- validator fixtures: the validator's pubkey, withdrawal_credentials and
  effective_balance, the state's genesis_validators_root (mainnet) and
  fork.current_version (Fulu) are proven. No separate bound check on the
  index is needed: a list slot past the registry length is a zero chunk, so a
  branch that reaches a field below it would need a SHA-256 preimage of zero.
  The registry length is read from the branch's length node and reported.

Fixtures of other kinds are skipped. The exit status is nonzero on any failure.
"""

import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt

GENESIS_TIME = 1606824023
SECONDS_PER_SLOT = 12
SLOTS_PER_EPOCH = 32
FULU_FORK_EPOCH = 411392
FULU_FORK_VERSION = bytes.fromhex("06000000")
MAINNET_GENESIS_VALIDATORS_ROOT = bytes.fromhex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")

HEADER_FIELDS = 5
BODY_FIELDS = 13
PAYLOAD_FIELDS = 17
STATE_FIELDS = 38
FORK_FIELDS = 3
VALIDATOR_FIELDS = 8
VALIDATOR_REGISTRY_DEPTH = 40

HEADER_STATE_ROOT = 3
HEADER_BODY_ROOT = 4
BODY_EXECUTION_PAYLOAD = 9
PAYLOAD_INDEX = {"state_root": 2, "block_number": 6, "block_hash": 12}
STATE_GENESIS_VALIDATORS_ROOT = 1
STATE_FORK = 3
FORK_CURRENT_VERSION = 1
STATE_VALIDATORS = 11
VALIDATOR_INDEX = {"pubkey": 0, "withdrawal_credentials": 1, "effective_balance": 2}
LIST_LENGTH_SIBLING = 3 + VALIDATOR_REGISTRY_DEPTH

BEACON_KINDS = ("beacon_chain", "beacon_validator")
CONSENSUS_VERSION = "fulu"
HEADER_KEYS = {"slot", "proposer_index", "parent_root", "state_root", "body_root"}
PROOF_KEYS = {"field", "gindex", "leaf", "branch"}
CHAIN_KEYS = {"name", "kind", "consensusVersion", "beacon", "execution", "proofs"}
VALIDATOR_KEYS = {"name", "kind", "consensusVersion", "beacon", "execution", "capture", "validatorIndex", "validator", "proofs"}
VALIDATOR_RECORD_KEYS = {"pubkey", "withdrawal_credentials", "effective_balance"}
CAPTURE_KEYS = {"finalized", "canonical"}


class CheckError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).digest()


def expect_keys(obj, keys, what):
    if not isinstance(obj, dict):
        raise CheckError(f"{what} is not an object")
    if set(obj) != keys:
        raise CheckError(f"{what} keys {sorted(obj)} differ from {sorted(keys)}")


def word(text):
    try:
        return oracle_mpt.hex_bytes(text, 32)
    except oracle_mpt.ProofError as e:
        raise CheckError(str(e)) from None


def hex_value(text, length):
    try:
        return oracle_mpt.hex_bytes(text, length)
    except oracle_mpt.ProofError as e:
        raise CheckError(str(e)) from None


def decimal(text, what):
    if not isinstance(text, str) or not text.isascii() or not text.isdigit() or (len(text) > 1 and text[0] == "0"):
        raise CheckError(f"{what} {text!r} is not a canonical decimal string")
    return int(text)


def depth_for(fields):
    depth = 0
    while (1 << depth) < fields:
        depth += 1
    return depth


def field_gindex(fields, index):
    if not 0 <= index < fields:
        raise CheckError(f"field index {index} outside a {fields} field container")
    return (1 << depth_for(fields)) + index


def concat(outer, inner):
    shift = inner.bit_length() - 1
    return (outer << shift) | (inner - (1 << shift))


def payload_gindex(field):
    body = concat(field_gindex(HEADER_FIELDS, HEADER_BODY_ROOT), field_gindex(BODY_FIELDS, BODY_EXECUTION_PAYLOAD))
    return concat(body, field_gindex(PAYLOAD_FIELDS, PAYLOAD_INDEX[field]))


def validator_state_gindex(index, field):
    if not 0 <= index < (1 << VALIDATOR_REGISTRY_DEPTH):
        raise CheckError(f"validator index {index} outside the registry limit")
    validators = field_gindex(STATE_FIELDS, STATE_VALIDATORS)
    list_data = concat(validators, 2)
    element = concat(list_data, (1 << VALIDATOR_REGISTRY_DEPTH) + index)
    return concat(element, field_gindex(VALIDATOR_FIELDS, VALIDATOR_INDEX[field]))


def state_gindex(field):
    if field == "genesis_validators_root":
        return field_gindex(STATE_FIELDS, STATE_GENESIS_VALIDATORS_ROOT)
    if field == "fork.current_version":
        return concat(field_gindex(STATE_FIELDS, STATE_FORK), field_gindex(FORK_FIELDS, FORK_CURRENT_VERSION))
    raise CheckError(f"unknown state field {field}")


def from_block_root(in_state):
    return concat(field_gindex(HEADER_FIELDS, HEADER_STATE_ROOT), in_state)


def uint64_leaf(value):
    if not 0 <= value < (1 << 64):
        raise CheckError(f"{value} does not fit uint64")
    return value.to_bytes(8, "little") + bytes(24)


def merkleize(chunks):
    width = 1
    while width < len(chunks):
        width *= 2
    layer = list(chunks) + [bytes(32)] * (width - len(chunks))
    while len(layer) > 1:
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def pubkey_leaf(pubkey):
    return sha256(pubkey[:32] + pubkey[32:] + bytes(16))


def parse_header(header):
    expect_keys(header, HEADER_KEYS, "beacon header")
    return {
        "slot": decimal(header["slot"], "slot"),
        "proposer_index": decimal(header["proposer_index"], "proposer_index"),
        "parent_root": word(header["parent_root"]),
        "state_root": word(header["state_root"]),
        "body_root": word(header["body_root"]),
    }


def header_root(header):
    return merkleize(
        [
            uint64_leaf(header["slot"]),
            uint64_leaf(header["proposer_index"]),
            header["parent_root"],
            header["state_root"],
            header["body_root"],
        ]
    )


def walk(leaf, gindex, branch):
    if gindex < 1:
        raise CheckError(f"generalized index {gindex} is not positive")
    if len(branch) != gindex.bit_length() - 1:
        raise CheckError(f"branch has {len(branch)} nodes, gindex {gindex} needs {gindex.bit_length() - 1}")
    node = leaf
    for level, sibling in enumerate(branch):
        if (gindex >> level) & 1:
            node = sha256(sibling + node)
        else:
            node = sha256(node + sibling)
    return node


def parse_proofs(proofs, expected, root):
    if not isinstance(proofs, list):
        raise CheckError("proofs is not a list")
    parsed = {}
    for proof in proofs:
        expect_keys(proof, PROOF_KEYS, "proof")
        field = proof["field"]
        if field not in expected:
            raise CheckError(f"unknown proof field {field!r}")
        if field in parsed:
            raise CheckError(f"duplicate proof for {field}")
        gindex_expected, leaf_expected = expected[field]
        gindex = decimal(proof["gindex"], f"{field} gindex")
        if gindex != gindex_expected:
            raise CheckError(f"{field}: gindex {gindex}, expected {gindex_expected}")
        leaf = word(proof["leaf"])
        if leaf != leaf_expected:
            raise CheckError(f"{field}: leaf {proof['leaf']} does not encode the recorded value")
        if not isinstance(proof["branch"], list):
            raise CheckError(f"{field}: branch is not a list")
        branch = [word(node) for node in proof["branch"]]
        if walk(leaf, gindex, branch) != root:
            raise CheckError(f"{field}: branch does not lead to the block root")
        parsed[field] = {"gindex": gindex, "leaf": leaf, "branch": branch}
    missing = sorted(set(expected) - set(parsed))
    if missing:
        raise CheckError(f"missing proofs {missing}")
    return parsed


def check_beacon(fixture, keys):
    expect_keys(fixture, keys, "fixture")
    if fixture["consensusVersion"] != CONSENSUS_VERSION:
        raise CheckError(f"unsupported consensus version {fixture['consensusVersion']!r}")
    beacon = fixture["beacon"]
    expect_keys(beacon, {"blockRoot", "header"}, "beacon")
    root = word(beacon["blockRoot"])
    header = parse_header(beacon["header"])
    if header_root(header) != root:
        raise CheckError("header fields do not hash to the block root")
    if header["slot"] < FULU_FORK_EPOCH * SLOTS_PER_EPOCH:
        raise CheckError(f"slot {header['slot']} is before the Fulu fork")
    return root, header


def check_execution(execution, keys, root, slot):
    expect_keys(execution, keys, "execution")
    header, child = execution["header"], execution["childHeader"]
    try:
        for h in (header, child):
            oracle_mpt.check_header(h)
        number = oracle_mpt.to_int(header["number"])
        child_number = oracle_mpt.to_int(child["number"])
        timestamp = oracle_mpt.to_int(header["timestamp"])
    except oracle_mpt.ProofError as e:
        raise CheckError(f"execution header: {e}") from None
    if child_number != number + 1:
        raise CheckError("child header is not the next block")
    if word(child["parentHash"]) != word(header["hash"]):
        raise CheckError("child header does not extend the recorded block")
    if word(child["parentBeaconBlockRoot"]) != root:
        raise CheckError("child parentBeaconBlockRoot is not the beacon block root")
    if timestamp != GENESIS_TIME + SECONDS_PER_SLOT * slot:
        raise CheckError(f"execution timestamp {timestamp} is not the time of slot {slot}")
    return {
        "number": number,
        "hash": word(header["hash"]),
        "state_root": word(header["stateRoot"]),
        "child_number": child_number,
        "child_timestamp": oracle_mpt.to_int(child["timestamp"]),
    }


def check_trie_links(names, execution, fixtures_dir):
    if not isinstance(names, list) or not names or len(set(names)) != len(names):
        raise CheckError("mptFixtures must list distinct fixture names")
    for name in names:
        path = fixtures_dir / f"{name}.json"
        if not path.exists():
            raise CheckError(f"listed trie fixture {name} does not exist")
        try:
            result = oracle_mpt.analyze(json.loads(path.read_text()))
        except oracle_mpt.ProofError as e:
            raise CheckError(f"listed trie fixture {name}: {e}") from None
        if result["block_hash"] != execution["hash"] or result["state_root"] != execution["state_root"]:
            raise CheckError(f"listed trie fixture {name} is from a different block")


def analyze_chain(fixture, fixtures_dir):
    root, header = check_beacon(fixture, CHAIN_KEYS)
    execution = check_execution(fixture["execution"], {"header", "childHeader", "mptFixtures"}, root, header["slot"])
    check_trie_links(fixture["execution"]["mptFixtures"], execution, fixtures_dir)
    expected = {
        "execution_payload.state_root": (payload_gindex("state_root"), execution["state_root"]),
        "execution_payload.block_number": (payload_gindex("block_number"), uint64_leaf(execution["number"])),
        "execution_payload.block_hash": (payload_gindex("block_hash"), execution["hash"]),
    }
    proofs = parse_proofs(fixture["proofs"], expected, root)
    return {"kind": "beacon_chain", "root": root, "header": header, "execution": execution, "proofs": proofs}


def analyze_validator(fixture, fixtures_dir):
    root, header = check_beacon(fixture, VALIDATOR_KEYS)
    execution = check_execution(fixture["execution"], {"header", "childHeader"}, root, header["slot"])
    expect_keys(fixture["capture"], CAPTURE_KEYS, "capture")
    if fixture["capture"] != {"finalized": True, "canonical": True}:
        raise CheckError("capture did not record a finalized canonical block")
    index = decimal(fixture["validatorIndex"], "validatorIndex")
    record = fixture["validator"]
    expect_keys(record, VALIDATOR_RECORD_KEYS, "validator")
    pubkey = hex_value(record["pubkey"], 48)
    credentials = word(record["withdrawal_credentials"])
    balance = decimal(record["effective_balance"], "effective_balance")
    prefix = f"validators[{index}]."
    expected = {
        prefix + "pubkey": (from_block_root(validator_state_gindex(index, "pubkey")), pubkey_leaf(pubkey)),
        prefix + "withdrawal_credentials": (
            from_block_root(validator_state_gindex(index, "withdrawal_credentials")),
            credentials,
        ),
        prefix + "effective_balance": (
            from_block_root(validator_state_gindex(index, "effective_balance")),
            uint64_leaf(balance),
        ),
        "genesis_validators_root": (from_block_root(state_gindex("genesis_validators_root")), MAINNET_GENESIS_VALIDATORS_ROOT),
        "fork.current_version": (from_block_root(state_gindex("fork.current_version")), FULU_FORK_VERSION + bytes(28)),
    }
    proofs = parse_proofs(fixture["proofs"], expected, root)
    registry = int.from_bytes(proofs[prefix + "pubkey"]["branch"][LIST_LENGTH_SIBLING], "little")
    return {
        "kind": "beacon_validator",
        "root": root,
        "header": header,
        "execution": execution,
        "index": index,
        "pubkey": pubkey,
        "credentials": credentials,
        "balance": balance,
        "registry": registry,
        "prefix": prefix,
        "proofs": proofs,
    }


def analyze(fixture, fixtures_dir):
    kind = fixture.get("kind") if isinstance(fixture, dict) else None
    if kind == "beacon_chain":
        return analyze_chain(fixture, fixtures_dir)
    if kind == "beacon_validator":
        return analyze_validator(fixture, fixtures_dir)
    raise CheckError(f"not a beacon fixture: kind {kind!r}")


def check_fixture(fixture, fixtures_dir):
    result = analyze(fixture, fixtures_dir)
    lines = [f"block root verified for slot {result['header']['slot']}"]
    lines.append(
        f"execution block {result['execution']['number']}; 4788 key is child timestamp "
        f"{result['execution']['child_timestamp']}"
    )
    if result["kind"] == "beacon_chain":
        lines.append("payload state_root, block_number, block_hash proven; trie fixtures linked")
    else:
        lines.append(
            f"validator {result['index']} of {result['registry']}: pubkey, withdrawal_credentials, "
            "effective_balance proven; mainnet genesis root and Fulu fork proven"
        )
    return lines


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    failures = 0
    for text in argv[1:]:
        path = pathlib.Path(text)
        try:
            fixture = json.loads(path.read_text())
            if not isinstance(fixture, dict) or fixture.get("kind") not in BEACON_KINDS:
                print(f"skip {path.name}: kind {fixture.get('kind') if isinstance(fixture, dict) else None}")
                continue
            for line in check_fixture(fixture, path.parent):
                print(f"ok   {path.name}: {line}")
        except (CheckError, KeyError, TypeError, ValueError) as e:
            print(f"FAIL {path.name}: {type(e).__name__}: {e}")
            failures += 1
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv)
