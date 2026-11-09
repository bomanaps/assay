"""Independent SSZ checker for beacon fixtures.

usage: oracle_ssz.py <fixture.json> [...]

Uses hashlib SHA-256 only and shares no code with remerkleable. For each
fixture it recomputes the beacon block root from the five header fields,
re-derives every generalized index from the container field counts, walks
every branch from its leaf to the block root, and checks the links between the
beacon proofs and the execution headers recorded with them. The exit status is
nonzero on any failure.
"""

import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt

HEADER_FIELDS = 5
BODY_FIELDS = 13
PAYLOAD_FIELDS = 17
STATE_FIELDS = 38
VALIDATOR_FIELDS = 8
VALIDATOR_REGISTRY_DEPTH = 40

HEADER_STATE_ROOT = 3
HEADER_BODY_ROOT = 4
BODY_EXECUTION_PAYLOAD = 9
PAYLOAD_INDEX = {"state_root": 2, "block_number": 6, "block_hash": 12}
STATE_VALIDATORS = 11
VALIDATOR_INDEX = {"withdrawal_credentials": 1, "effective_balance": 2}
SUPPORTED_VERSIONS = {"fulu"}


class CheckError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).digest()


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


def validator_gindex(index, field):
    if not 0 <= index < (1 << VALIDATOR_REGISTRY_DEPTH):
        raise CheckError(f"validator index {index} outside the registry limit")
    validators = field_gindex(STATE_FIELDS, STATE_VALIDATORS)
    list_data = concat(validators, 2)
    element = concat(list_data, (1 << VALIDATOR_REGISTRY_DEPTH) + index)
    in_state = concat(element, field_gindex(VALIDATOR_FIELDS, VALIDATOR_INDEX[field]))
    return concat(field_gindex(HEADER_FIELDS, HEADER_STATE_ROOT), in_state)


def word(text):
    digits = text[2:] if text.startswith("0x") else text
    if len(digits) != 64:
        raise CheckError(f"{text} is not 32 bytes")
    return bytes.fromhex(digits)


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


def header_root(header):
    return merkleize(
        [
            uint64_leaf(int(header["slot"])),
            uint64_leaf(int(header["proposer_index"])),
            word(header["parent_root"]),
            word(header["state_root"]),
            word(header["body_root"]),
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


def check_proof(proof, expected_gindex, expected_leaf, root):
    gindex = int(proof["gindex"])
    if gindex != expected_gindex:
        raise CheckError(f"{proof['field']}: gindex {gindex}, expected {expected_gindex}")
    leaf = word(proof["leaf"])
    if leaf != expected_leaf:
        raise CheckError(f"{proof['field']}: leaf {proof['leaf']} does not encode the recorded value")
    branch = [word(node) for node in proof["branch"]]
    if walk(leaf, gindex, branch) != root:
        raise CheckError(f"{proof['field']}: branch does not lead to the block root")


def check_beacon(fixture):
    if fixture.get("consensusVersion") not in SUPPORTED_VERSIONS:
        raise CheckError(f"unsupported consensus version {fixture.get('consensusVersion')}")
    beacon = fixture["beacon"]
    root = word(beacon["blockRoot"])
    if header_root(beacon["header"]) != root:
        raise CheckError("header fields do not hash to the block root")
    return root


def check_chain(fixture):
    root = check_beacon(fixture)
    execution = fixture["execution"]
    header = execution["header"]
    child = execution["childHeader"]
    for h in (header, child):
        oracle_mpt.check_header(h)
    if int(child["number"], 16) != int(header["number"], 16) + 1:
        raise CheckError("child header is not the next block")
    if word(child["parentHash"]) != word(header["hash"]):
        raise CheckError("child header does not extend the recorded block")
    if word(child["parentBeaconBlockRoot"]) != root:
        raise CheckError("child parentBeaconBlockRoot is not the beacon block root")
    values = {
        "state_root": word(header["stateRoot"]),
        "block_number": uint64_leaf(int(header["number"], 16)),
        "block_hash": word(header["hash"]),
    }
    seen = set()
    for proof in fixture["proofs"]:
        field = proof["field"].removeprefix("execution_payload.")
        if field not in PAYLOAD_INDEX:
            raise CheckError(f"unknown payload field {proof['field']}")
        check_proof(proof, payload_gindex(field), values[field], root)
        seen.add(field)
    if seen != set(PAYLOAD_INDEX):
        raise CheckError(f"missing payload proofs {sorted(set(PAYLOAD_INDEX) - seen)}")
    return [
        f"block root verified for slot {fixture['beacon']['header']['slot']}",
        f"payload of block {int(header['number'], 16)}: state_root, block_number, block_hash proven",
        f"4788 key: child block timestamp {int(child['timestamp'], 16)}",
    ]


def check_validator(fixture):
    root = check_beacon(fixture)
    index = int(fixture["validatorIndex"])
    validator = fixture["validator"]
    values = {
        "withdrawal_credentials": word(validator["withdrawal_credentials"]),
        "effective_balance": uint64_leaf(int(validator["effective_balance"])),
    }
    seen = set()
    for proof in fixture["proofs"]:
        field = proof["field"].removeprefix(f"validators[{index}].")
        if field not in VALIDATOR_INDEX:
            raise CheckError(f"unknown validator field {proof['field']}")
        check_proof(proof, validator_gindex(index, field), values[field], root)
        seen.add(field)
    if seen != set(VALIDATOR_INDEX):
        raise CheckError(f"missing validator proofs {sorted(set(VALIDATOR_INDEX) - seen)}")
    return [
        f"block root verified for slot {fixture['beacon']['header']['slot']}",
        f"validator {index}: withdrawal_credentials and effective_balance proven",
    ]


def check_fixture(fixture):
    kind = fixture.get("kind")
    if kind == "beacon_chain":
        return check_chain(fixture)
    if kind == "beacon_validator":
        return check_validator(fixture)
    raise CheckError(f"unknown fixture kind {kind}")


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    failures = 0
    for text in argv[1:]:
        path = pathlib.Path(text)
        fixture = json.loads(path.read_text())
        try:
            for line in check_fixture(fixture):
                print(f"ok   {path.name}: {line}")
        except (CheckError, oracle_mpt.ProofError, KeyError, ValueError) as e:
            print(f"FAIL {path.name}: {e}")
            failures += 1
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv)
