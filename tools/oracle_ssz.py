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
  child's timestamp; the child's timestamp must be a later slot time. The
  child header is bound to the recorded block by its parentHash only, so its
  timestamp, the 4788 key, rests on the capture-time RPC answer;
- chain fixtures: the payload's state_root, block_number and block_hash equal
  that execution block, and the trie fixtures listed in mptFixtures exist next
  to it, pass oracle_mpt.py, and were captured at that same block;
- validator fixtures: the whole validator record, whose root is recomputed
  from its eight fields, and separately its pubkey, withdrawal_credentials and
  effective_balance, the state's genesis_validators_root (mainnet) and
  fork.current_version (Fulu) are proven, and the state's
  latest_execution_payload_header.block_hash must equal the recorded execution
  block, which binds that block to the beacon root. No separate bound check on the
  index is needed: a list slot past the registry length is a zero chunk, so a
  branch that reaches a field below it would need a SHA-256 preimage of zero.
  The registry length is read from the branch's length node and reported.

Fixtures of other kinds are skipped. The exit status is nonzero on any failure.
"""

import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt
import oracle_receipt

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
PAYLOAD_INDEX = {"state_root": 2, "receipts_root": 3, "block_number": 6, "block_hash": 12}
STATE_GENESIS_VALIDATORS_ROOT = 1
STATE_FORK = 3
FORK_CURRENT_VERSION = 1
STATE_LATEST_EXECUTION_PAYLOAD_HEADER = 24
STATE_VALIDATORS = 11
STATE_BLOCK_ROOTS = 5
SLOTS_PER_HISTORICAL_ROOT = 8192
STATE_HISTORICAL_SUMMARIES = 27
HISTORICAL_SUMMARIES_LIMIT = 1 << 24
SUMMARY_FIELDS = 2
CAPELLA_FIRST_PERIOD = 758
CAPELLA_FIRST_SLOT = CAPELLA_FIRST_PERIOD * SLOTS_PER_HISTORICAL_ROOT
VALIDATOR_INDEX = {"pubkey": 0, "withdrawal_credentials": 1, "effective_balance": 2}
VALIDATOR_EPOCHS = ("activation_eligibility_epoch", "activation_epoch", "exit_epoch", "withdrawable_epoch")
LIST_LENGTH_SIBLING = 3 + VALIDATOR_REGISTRY_DEPTH

BEACON_KINDS = ("beacon_chain", "beacon_validator", "beacon_history", "beacon_deephistory")
FRAME_KIND = "frame_gloas"
GLOAS_STATE_FIELDS = 46
GLOAS_LATEST_BLOCK_HASH_FIELD = 24
EXECUTION_STATE_ROOT_FIELD = 3
EXECUTION_NUMBER_FIELD = 8
EXECUTION_TIMESTAMP_FIELD = 11
HISTORY_BUFFER_LENGTH = 8191
BEACON_ROOTS_ADDRESS = "0x000f3df6d732807ef1319fb7b8bb8522d0beac02"
FRAME_KEYS = {
    "name",
    "kind",
    "network",
    "chainId",
    "specCommit",
    "fork",
    "endpoints",
    "beaconRoot",
    "beaconHeader",
    "latestBlockHashGindex",
    "latestBlockHash",
    "latestBlockHashBranch",
    "executionHeaderRlp",
    "executionHeader",
    "account",
    "timestampSlot",
    "rootSlot",
    "proof",
}
FIXTURE_NAME = re.compile(r"[a-z][a-z0-9_]*")
CONSENSUS_VERSION = "fulu"
HEADER_KEYS = {"slot", "proposer_index", "parent_root", "state_root", "body_root"}
PROOF_KEYS = {"field", "gindex", "leaf", "branch"}
CHAIN_KEYS = {"name", "kind", "consensusVersion", "beacon", "execution", "proofs"}
CHAIN_KEYS_MULTI = CHAIN_KEYS | {"payloadMultiproof"}
VALIDATOR_KEYS = {"name", "kind", "consensusVersion", "beacon", "execution", "capture", "validatorIndex", "validator", "proofs"}
VALIDATOR_RECORD_KEYS = {"pubkey", "withdrawal_credentials", "effective_balance", "slashed", *VALIDATOR_EPOCHS}
CAPTURE_KEYS = {"finalized", "canonical"}
HISTORY_KEYS = {"name", "kind", "consensusVersion", "beacon", "execution", "capture", "targetSlot", "historicalRoot", "proofs"}
DEEPHISTORY_KEYS = {"name", "kind", "consensusVersion", "beacon", "execution", "capture", "targetSlot", "historicalRoot", "summaryIndex", "summaryRoot", "proofs"}


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


def block_root_element_gindex(index):
    if not 0 <= index < SLOTS_PER_HISTORICAL_ROOT:
        raise CheckError(f"block root index {index} outside the historical vector")
    return concat(field_gindex(STATE_FIELDS, STATE_BLOCK_ROOTS), SLOTS_PER_HISTORICAL_ROOT + index)


def summary_block_root_gindex(index):
    if not 0 <= index < HISTORICAL_SUMMARIES_LIMIT:
        raise CheckError(f"summary index {index} outside the list limit")
    summaries = field_gindex(STATE_FIELDS, STATE_HISTORICAL_SUMMARIES)
    element = concat(concat(summaries, 2), HISTORICAL_SUMMARIES_LIMIT + index)
    return concat(element, field_gindex(SUMMARY_FIELDS, 0))


def validator_element_gindex(index):
    if not 0 <= index < (1 << VALIDATOR_REGISTRY_DEPTH):
        raise CheckError(f"validator index {index} outside the registry limit")
    validators = field_gindex(STATE_FIELDS, STATE_VALIDATORS)
    list_data = concat(validators, 2)
    return concat(list_data, (1 << VALIDATOR_REGISTRY_DEPTH) + index)


def validator_state_gindex(index, field):
    return concat(validator_element_gindex(index), field_gindex(VALIDATOR_FIELDS, VALIDATOR_INDEX[field]))


def state_gindex(field):
    if field == "genesis_validators_root":
        return field_gindex(STATE_FIELDS, STATE_GENESIS_VALIDATORS_ROOT)
    if field == "fork.current_version":
        return concat(field_gindex(STATE_FIELDS, STATE_FORK), field_gindex(FORK_FIELDS, FORK_CURRENT_VERSION))
    if field == "latest_execution_payload_header.block_hash":
        return concat(
            field_gindex(STATE_FIELDS, STATE_LATEST_EXECUTION_PAYLOAD_HEADER),
            field_gindex(PAYLOAD_FIELDS, PAYLOAD_INDEX["block_hash"]),
        )
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


def parse_validator(record):
    expect_keys(record, VALIDATOR_RECORD_KEYS, "validator")
    if not isinstance(record["slashed"], bool):
        raise CheckError("validator slashed is not a boolean")
    parsed = {
        "pubkey": hex_value(record["pubkey"], 48),
        "withdrawal_credentials": word(record["withdrawal_credentials"]),
        "effective_balance": decimal(record["effective_balance"], "effective_balance"),
        "slashed": record["slashed"],
    }
    for name in VALIDATOR_EPOCHS:
        parsed[name] = decimal(record[name], name)
    return parsed


def validator_root(record):
    return merkleize(
        [
            pubkey_leaf(record["pubkey"]),
            record["withdrawal_credentials"],
            uint64_leaf(record["effective_balance"]),
            bytes([record["slashed"]]) + bytes(31),
        ]
        + [uint64_leaf(record[name]) for name in VALIDATOR_EPOCHS]
    )


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


def multiproof_helper_indices(indices):
    all_helper = set()
    all_path = set()
    for index in indices:
        if index < 1:
            raise CheckError(f"generalized index {index} is not positive")
        k = index
        while k > 1:
            all_helper.add(k ^ 1)
            all_path.add(k)
            k //= 2
    return sorted(all_helper - all_path, reverse=True)


def calculate_multi_merkle_root(leaves, helpers, indices):
    if len(leaves) != len(indices):
        raise CheckError("leaf count differs from index count")
    expected_helpers = multiproof_helper_indices(indices)
    if len(helpers) != len(expected_helpers):
        raise CheckError(f"helper count {len(helpers)}, expected {len(expected_helpers)}")
    objects = {}
    for index, leaf in zip(indices, leaves):
        objects[index] = leaf
    for index, helper in zip(expected_helpers, helpers):
        objects[index] = helper
    keys = sorted(objects, reverse=True)
    position = 0
    while position < len(keys):
        k = keys[position]
        if k > 1 and (k ^ 1) in objects and k // 2 not in objects:
            objects[k // 2] = sha256(objects[k & ~1] + objects[k | 1])
            keys.append(k // 2)
            keys.sort(reverse=True)
        position += 1
    if 1 not in objects:
        raise CheckError("the multiproof does not reach the root")
    return objects[1]


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
    child_timestamp = oracle_mpt.to_int(child["timestamp"])
    if child_timestamp <= timestamp or (child_timestamp - GENESIS_TIME) % SECONDS_PER_SLOT:
        raise CheckError(f"child timestamp {child_timestamp} is not a later slot time")
    return {
        "number": number,
        "hash": word(header["hash"]),
        "state_root": word(header["stateRoot"]),
        "child_number": child_number,
        "child_timestamp": child_timestamp,
    }


def check_trie_links(names, execution, fixtures_dir):
    if not isinstance(names, list) or not names or len(set(names)) != len(names):
        raise CheckError("mptFixtures must list distinct fixture names")
    for name in names:
        if not isinstance(name, str) or not FIXTURE_NAME.fullmatch(name):
            raise CheckError(f"listed trie fixture name {name!r} is not a fixture name")
        path = fixtures_dir / f"{name}.json"
        if not path.exists():
            raise CheckError(f"listed trie fixture {name} does not exist")
        try:
            result = oracle_mpt.analyze(json.loads(path.read_text()))
        except oracle_mpt.ProofError as e:
            raise CheckError(f"listed trie fixture {name}: {e}") from None
        if json.loads(path.read_text())["name"] != name:
            raise CheckError(f"listed trie fixture file {name}.json holds another fixture")
        if result["block_hash"] != execution["hash"] or result["state_root"] != execution["state_root"]:
            raise CheckError(f"listed trie fixture {name} is from a different block")


def check_receipt_links(names, execution, receipts_root, fixtures_dir):
    if not isinstance(names, list) or not names or len(set(names)) != len(names):
        raise CheckError("receiptFixtures must list distinct fixture names")
    for name in names:
        if not isinstance(name, str) or not FIXTURE_NAME.fullmatch(name):
            raise CheckError(f"listed receipt fixture name {name!r} is not a fixture name")
        path = fixtures_dir / f"{name}.json"
        if not path.exists():
            raise CheckError(f"listed receipt fixture {name} does not exist")
        loaded = json.loads(path.read_text())
        if loaded["name"] != name:
            raise CheckError(f"listed receipt fixture file {name}.json holds another fixture")
        try:
            result = oracle_receipt.analyze(loaded)
        except oracle_receipt.ReceiptError as e:
            raise CheckError(f"listed receipt fixture {name}: {e}") from None
        if result["block_hash"] != execution["hash"] or result["receipts_root"] != receipts_root:
            raise CheckError(f"listed receipt fixture {name} is from a different block")


def check_payload_multiproof(fixture, proofs, root):
    multi = fixture["payloadMultiproof"]
    expect_keys(multi, {"gindices", "helpers"}, "payloadMultiproof")
    indices = [decimal(i, "multiproof gindex") for i in multi["gindices"]]
    if len(set(indices)) != len(indices):
        raise CheckError("multiproof gindices hold duplicates")
    by_gindex = {}
    for p in proofs.values():
        by_gindex.setdefault(int(p["gindex"]), p)
    missing = [i for i in indices if i not in by_gindex]
    if missing:
        raise CheckError(f"multiproof gindices {missing} name no recorded proof")
    leaves = [by_gindex[i]["leaf"] for i in indices]
    helpers = [word(h) for h in multi["helpers"]]
    reconstructed = calculate_multi_merkle_root(leaves, helpers, indices)
    if reconstructed != root:
        raise CheckError("the payload multiproof does not reconstruct the anchor root")
    return len(helpers)


def analyze_chain(fixture, fixtures_dir):
    has_multi = isinstance(fixture, dict) and "payloadMultiproof" in fixture
    root, header = check_beacon(fixture, CHAIN_KEYS_MULTI if has_multi else CHAIN_KEYS)
    execution_keys = {"header", "childHeader", "mptFixtures"}
    has_receipts = isinstance(fixture.get("execution"), dict) and "receiptFixtures" in fixture["execution"]
    if has_receipts:
        execution_keys.add("receiptFixtures")
    execution = check_execution(fixture["execution"], execution_keys, root, header["slot"])
    expected = {
        "execution_payload.state_root": (payload_gindex("state_root"), execution["state_root"]),
        "execution_payload.block_number": (payload_gindex("block_number"), uint64_leaf(execution["number"])),
        "execution_payload.block_hash": (payload_gindex("block_hash"), execution["hash"]),
    }
    if has_receipts:
        receipts_root = word(fixture["execution"]["header"]["receiptsRoot"])
        expected["execution_payload.receipts_root"] = (payload_gindex("receipts_root"), receipts_root)
    proofs = parse_proofs(fixture["proofs"], expected, root)
    check_trie_links(fixture["execution"]["mptFixtures"], execution, fixtures_dir)
    if has_receipts:
        check_receipt_links(fixture["execution"]["receiptFixtures"], execution, receipts_root, fixtures_dir)
    result = {"kind": "beacon_chain", "root": root, "header": header, "execution": execution, "proofs": proofs}
    if has_multi:
        result["multiproof_helpers"] = check_payload_multiproof(fixture, proofs, root)
    return result


def analyze_validator(fixture, fixtures_dir):
    root, header = check_beacon(fixture, VALIDATOR_KEYS)
    execution = check_execution(fixture["execution"], {"header", "childHeader"}, root, header["slot"])
    expect_keys(fixture["capture"], CAPTURE_KEYS, "capture")
    if fixture["capture"]["finalized"] is not True or fixture["capture"]["canonical"] is not True:
        raise CheckError("capture did not record a finalized canonical block")
    index = decimal(fixture["validatorIndex"], "validatorIndex")
    record = parse_validator(fixture["validator"])
    pubkey = record["pubkey"]
    credentials = record["withdrawal_credentials"]
    balance = record["effective_balance"]
    prefix = f"validators[{index}]."
    expected = {
        f"validators[{index}]": (from_block_root(validator_element_gindex(index)), validator_root(record)),
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
        "latest_execution_payload_header.block_hash": (
            from_block_root(state_gindex("latest_execution_payload_header.block_hash")),
            execution["hash"],
        ),
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
        "record": record,
        "registry": registry,
        "prefix": prefix,
        "proofs": proofs,
    }


def analyze_history(fixture, fixtures_dir):
    root, header = check_beacon(fixture, HISTORY_KEYS)
    execution = check_execution(fixture["execution"], {"header", "childHeader"}, root, header["slot"])
    expect_keys(fixture["capture"], CAPTURE_KEYS, "capture")
    if fixture["capture"]["finalized"] is not True or fixture["capture"]["canonical"] is not True:
        raise CheckError("capture did not record a finalized canonical block")
    target = decimal(fixture["targetSlot"], "targetSlot")
    slot = header["slot"]
    if not (target < slot and slot <= target + SLOTS_PER_HISTORICAL_ROOT):
        raise CheckError(f"target slot {target} is outside the historical window of slot {slot}")
    position = target % SLOTS_PER_HISTORICAL_ROOT
    stored = word(fixture["historicalRoot"])
    expected = {
        f"block_roots[{position}]": (from_block_root(block_root_element_gindex(position)), stored),
        "genesis_validators_root": (from_block_root(state_gindex("genesis_validators_root")), MAINNET_GENESIS_VALIDATORS_ROOT),
        "fork.current_version": (from_block_root(state_gindex("fork.current_version")), FULU_FORK_VERSION + bytes(28)),
        "latest_execution_payload_header.block_hash": (
            from_block_root(state_gindex("latest_execution_payload_header.block_hash")),
            execution["hash"],
        ),
    }
    proofs = parse_proofs(fixture["proofs"], expected, root)
    return {
        "kind": "beacon_history",
        "root": root,
        "header": header,
        "execution": execution,
        "target": target,
        "position": position,
        "historical_root": stored,
        "proofs": proofs,
    }


def analyze_deephistory(fixture, fixtures_dir):
    root, header = check_beacon(fixture, DEEPHISTORY_KEYS)
    execution = check_execution(fixture["execution"], {"header", "childHeader"}, root, header["slot"])
    expect_keys(fixture["capture"], CAPTURE_KEYS, "capture")
    if fixture["capture"]["finalized"] is not True or fixture["capture"]["canonical"] is not True:
        raise CheckError("capture did not record a finalized canonical block")
    target = decimal(fixture["targetSlot"], "targetSlot")
    slot = header["slot"]
    if target < CAPELLA_FIRST_SLOT:
        raise CheckError(f"target slot {target} is before Capella")
    period = target // SLOTS_PER_HISTORICAL_ROOT
    if period >= slot // SLOTS_PER_HISTORICAL_ROOT:
        raise CheckError(f"target slot {target} is in the anchor's own period")
    summary_index = decimal(fixture["summaryIndex"], "summaryIndex")
    if summary_index != period - CAPELLA_FIRST_PERIOD:
        raise CheckError(f"summary index {summary_index} does not match period {period}")
    position = target % SLOTS_PER_HISTORICAL_ROOT
    summary_root = word(fixture["summaryRoot"])
    stored = word(fixture["historicalRoot"])
    expected = {
        f"historical_summaries[{summary_index}].block_summary_root": (
            from_block_root(summary_block_root_gindex(summary_index)), summary_root,
        ),
        "genesis_validators_root": (from_block_root(state_gindex("genesis_validators_root")), MAINNET_GENESIS_VALIDATORS_ROOT),
        "fork.current_version": (from_block_root(state_gindex("fork.current_version")), FULU_FORK_VERSION + bytes(28)),
        "latest_execution_payload_header.block_hash": (
            from_block_root(state_gindex("latest_execution_payload_header.block_hash")),
            execution["hash"],
        ),
    }
    vector_name = f"block_summary[{position}]"
    vector_entries = [p for p in fixture["proofs"] if isinstance(p, dict) and p.get("field") == vector_name]
    if len(vector_entries) != 1:
        raise CheckError(f"the fixture must hold exactly one proof named {vector_name}")
    state_proofs = [p for p in fixture["proofs"] if not (isinstance(p, dict) and p.get("field") == vector_name)]
    proofs = parse_proofs(state_proofs, expected, root)
    vector_proofs = parse_proofs(vector_entries, {vector_name: (SLOTS_PER_HISTORICAL_ROOT + position, stored)}, summary_root)
    return {
        "kind": "beacon_deephistory",
        "root": root,
        "header": header,
        "execution": execution,
        "target": target,
        "period": period,
        "summary_index": summary_index,
        "position": position,
        "summary_root": summary_root,
        "historical_root": stored,
        "proofs": {**proofs, **vector_proofs},
    }


def progressive_field_gindex(fields, index):
    if not 0 <= index < fields:
        raise CheckError(f"field index {index} outside a {fields} field progressive container")
    depth, gindex = 0, 2
    while index >= 1 << depth:
        index -= 1 << depth
        depth += 2
        gindex = gindex * 2 + 1
    return ((gindex << 1) << depth) + index


def analyze_frame(fixture):
    expect_keys(fixture, FRAME_KEYS, "fixture")
    header = parse_header(fixture["beaconHeader"])
    root = word(fixture["beaconRoot"])
    if header_root(header) != root:
        raise CheckError("beacon header fields do not hash to the block root")

    gindex = decimal(fixture["latestBlockHashGindex"], "latestBlockHashGindex")
    expected = concat(
        field_gindex(HEADER_FIELDS, HEADER_STATE_ROOT),
        progressive_field_gindex(GLOAS_STATE_FIELDS, GLOAS_LATEST_BLOCK_HASH_FIELD),
    )
    if gindex != expected:
        raise CheckError(f"gindex {gindex} differs from the derived {expected}")
    leaf = word(fixture["latestBlockHash"])
    branch = [word(node) for node in fixture["latestBlockHashBranch"]]
    if walk(leaf, gindex, branch) != root:
        raise CheckError("the latest_block_hash branch does not reconstruct the block root")

    try:
        header_rlp = oracle_mpt.hex_bytes(fixture["executionHeaderRlp"])
        if oracle_mpt.keccak256(header_rlp) != leaf:
            raise CheckError("execution header RLP does not hash to latest_block_hash")
        items = oracle_mpt.rlp_decode(header_rlp)
        if not isinstance(items, list) or len(items) <= EXECUTION_TIMESTAMP_FIELD:
            raise CheckError("execution header RLP is not a long enough list")
        state_root = items[EXECUTION_STATE_ROOT_FIELD]
        if not isinstance(state_root, bytes) or len(state_root) != 32:
            raise CheckError("execution state root field is not 32 bytes")
        recorded = fixture["executionHeader"]
        expect_keys(
            recorded,
            {"number", "timestamp", "stateRoot", "parentBeaconBlockRoot"},
            "executionHeader",
        )
        if state_root != word(recorded["stateRoot"]):
            raise CheckError("recorded stateRoot differs from the RLP field")
        number = oracle_mpt.rlp_int(items[EXECUTION_NUMBER_FIELD])
        if number != oracle_mpt.to_int(recorded["number"]):
            raise CheckError("recorded number differs from the RLP field")
        timestamp = oracle_mpt.rlp_int(items[EXECUTION_TIMESTAMP_FIELD])
        if timestamp != oracle_mpt.to_int(recorded["timestamp"]):
            raise CheckError("recorded timestamp differs from the RLP field")

        proof = fixture["proof"]
        if fixture["account"] != BEACON_ROOTS_ADDRESS or proof["address"] != BEACON_ROOTS_ADDRESS:
            raise CheckError("the proven account is not the EIP-4788 contract")
        address = oracle_mpt.hex_bytes(proof["address"], 20)
        account_nodes = [oracle_mpt.hex_bytes(node) for node in proof["accountProof"]]
        account_leaf = oracle_mpt.walk(state_root, oracle_mpt.keccak256(address), account_nodes)
        if account_leaf is None:
            raise CheckError("the 4788 account is absent from the proof")
        account_fields = oracle_mpt.rlp_decode(account_leaf)
        if not isinstance(account_fields, list) or len(account_fields) != 4:
            raise CheckError("account leaf is not a 4 item list")
        storage_root = account_fields[2]

        timestamp_slot = oracle_mpt.to_int(fixture["timestampSlot"])
        root_slot = oracle_mpt.to_int(fixture["rootSlot"])
        if timestamp_slot != timestamp % HISTORY_BUFFER_LENGTH:
            raise CheckError("timestampSlot is not timestamp mod the ring length")
        if root_slot != timestamp_slot + HISTORY_BUFFER_LENGTH:
            raise CheckError("rootSlot is not the matching root index")

        slots = {}
        for entry in proof["storageProof"]:
            key = oracle_mpt.to_int(entry["key"])
            nodes = [oracle_mpt.hex_bytes(node) for node in entry["proof"]]
            value_rlp = oracle_mpt.walk(
                storage_root, oracle_mpt.keccak256(key.to_bytes(32, "big")), nodes
            )
            if value_rlp is None:
                raise CheckError(f"storage slot {key} is absent from the proof")
            slots[key] = {
                "value": oracle_mpt.rlp_int(oracle_mpt.rlp_decode(value_rlp)),
                "nodes": nodes,
            }
        if set(slots) != {timestamp_slot, root_slot}:
            raise CheckError("storage proofs do not cover the two ring buffer slots")
        if slots[timestamp_slot]["value"] != timestamp:
            raise CheckError("the ring buffer timestamp slot does not hold the block timestamp")
        parent_beacon_root = oracle_mpt.to_int(recorded["parentBeaconBlockRoot"])
        if slots[root_slot]["value"] != parent_beacon_root:
            raise CheckError("the ring buffer root slot does not hold the parent beacon root")
    except oracle_mpt.ProofError as e:
        raise CheckError(str(e)) from None

    return {
        "kind": FRAME_KIND,
        "header": header,
        "root": root,
        "gindex": gindex,
        "leaf": leaf,
        "branch": branch,
        "header_rlp": header_rlp,
        "state_root": state_root,
        "number": number,
        "timestamp": timestamp,
        "address": address,
        "account_nodes": account_nodes,
        "timestamp_slot": timestamp_slot,
        "root_slot": root_slot,
        "timestamp_nodes": slots[timestamp_slot]["nodes"],
        "root_nodes": slots[root_slot]["nodes"],
        "parent_beacon_root": parent_beacon_root,
    }


def analyze(fixture, fixtures_dir):
    kind = fixture.get("kind") if isinstance(fixture, dict) else None
    if kind == "beacon_chain":
        return analyze_chain(fixture, fixtures_dir)
    if kind == "beacon_validator":
        return analyze_validator(fixture, fixtures_dir)
    if kind == "beacon_history":
        return analyze_history(fixture, fixtures_dir)
    if kind == "beacon_deephistory":
        return analyze_deephistory(fixture, fixtures_dir)
    raise CheckError(f"not a beacon fixture: kind {kind!r}")


def check_fixture(fixture, fixtures_dir):
    result = analyze(fixture, fixtures_dir)
    lines = [f"block root verified for slot {result['header']['slot']}"]
    lines.append(
        f"execution block {result['execution']['number']}; 4788 key is child timestamp "
        f"{result['execution']['child_timestamp']}"
    )
    if result["kind"] == "beacon_chain":
        line = "payload state_root, block_number, block_hash proven; trie fixtures linked"
        if "multiproof_helpers" in result:
            line += f"; payload multiproof ({result['multiproof_helpers']} helpers) reconstructs the root"
        lines.append(line)
    elif result["kind"] == "beacon_deephistory":
        lines.append(
            f"latest block root at or before slot {result['target']} (period {result['period']}) proven "
            f"through summary {result['summary_index']} from the anchor at slot {result['header']['slot']}"
        )
    elif result["kind"] == "beacon_history":
        lines.append(
            f"latest block root at or before slot {result['target']} proven from the anchor at slot "
            f"{result['header']['slot']}; mainnet genesis root and Fulu fork proven"
        )
    else:
        lines.append(
            f"validator {result['index']} of {result['registry']}: whole record, pubkey, "
            "withdrawal_credentials, effective_balance proven; mainnet genesis root and Fulu fork proven"
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
