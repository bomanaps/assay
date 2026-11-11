"""Capture beacon chain proofs as fixtures.

usage: capture_beacon.py chain
       capture_beacon.py validator <state.ssz> <validator index> <fixture name>

Both read RPC_URL (execution JSON-RPC) and BEACON_URL (beacon API).

chain picks execution block N two blocks behind the head, reads block N+1, and
fetches the beacon block named by N+1's parentBeaconBlockRoot, whose execution
payload is N. It writes fixtures/chain_beacon.json with proofs of the payload's
state_root, block_number and block_hash against the beacon block root, and
trie fixtures captured at block N: chain_storage_usdc (slot 0, and slot
0xa55a70ff, which must be unset), chain_storage_weth (slots 0 to 2), and
chain_account_absent for an address that must hold no account.

validator takes a BeaconState in SSZ whose slot holds a finalized, canonical
block. It writes fixtures/<fixture name>.json, a name starting with
validator_, with the validator's eight
fields and proofs of the whole validator record, of its pubkey,
withdrawal_credentials and effective_balance, of the state's latest execution
payload block_hash, and of the state's
genesis_validators_root and fork.current_version, against that block's root.

Every computed root must equal the root the chain reports, every proof
position derived from the oracle's field counts must equal the one remerkleable
derives from its type tree, and oracle_ssz.py and oracle_mpt.py must accept
the new fixtures in a scratch directory. Only then are the files moved into
fixtures/. Requires remerkleable 0.1.28 and pycryptodome.
"""

import json
import os
import pathlib
import re
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from remerkleable.tree import concat_gindices

import capture_getproof
import oracle_mpt
import oracle_ssz
import ssz_types as t

USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
ABSENT = "0x00000000000000000000000000000000a55a70ff"
DECIMAL_PATTERN = re.compile(r"[0-9]+")
VALIDATOR_NAME_PATTERN = re.compile(r"validator_[a-z0-9_]+")


def fail(message):
    raise SystemExit(f"error: {message}")


def env(name):
    value = os.environ.get(name)
    if not value:
        fail(f"{name} is not set")
    return value.rstrip("/")


def beacon_get(path):
    request = urllib.request.Request(env("BEACON_URL") + path, headers={"user-agent": "assay-capture/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            reply = json.load(response)
    except urllib.error.HTTPError as e:
        fail(f"beacon {path}: HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        fail(f"beacon {path}: {e.reason}")
    except json.JSONDecodeError:
        fail(f"beacon {path}: reply is not JSON")
    if not isinstance(reply, dict) or "data" not in reply:
        fail(f"beacon {path}: reply has no data")
    return reply


def hex32(data):
    return "0x" + bytes(data).hex()


def type_gindex(cls, keys):
    parts = []
    for key in keys:
        parts.append(cls.key_to_static_gindex(key))
        cls = cls.fields()[key] if isinstance(key, str) else cls.element_cls()
    return int(concat_gindices(parts))


def branch(node, gindex):
    depth = gindex.bit_length() - 1
    siblings = []
    for level in range(depth - 1, -1, -1):
        if (gindex >> level) & 1:
            siblings.append(node.get_left().merkle_root())
            node = node.get_right()
        else:
            siblings.append(node.get_right().merkle_root())
            node = node.get_left()
    return bytes(node.merkle_root()), [bytes(s) for s in reversed(siblings)]


def header_json(header):
    return {
        "slot": str(int(header.slot)),
        "proposer_index": str(int(header.proposer_index)),
        "parent_root": hex32(header.parent_root),
        "state_root": hex32(header.state_root),
        "body_root": hex32(header.body_root),
    }


def proof_json(field, gindex, leaf, siblings):
    return {"field": field, "gindex": str(gindex), "leaf": hex32(leaf), "branch": [hex32(s) for s in siblings]}


def check_version(response):
    if response.get("version") != oracle_ssz.CONSENSUS_VERSION:
        fail(f"beacon version {response.get('version')}, this tool handles {oracle_ssz.CONSENSUS_VERSION}")


def check_network():
    spec = beacon_get("/eth/v1/config/spec")["data"]
    genesis = beacon_get("/eth/v1/beacon/genesis")["data"]
    expected = {
        "SECONDS_PER_SLOT": str(oracle_ssz.SECONDS_PER_SLOT),
        "FULU_FORK_EPOCH": str(oracle_ssz.FULU_FORK_EPOCH),
        "FULU_FORK_VERSION": hex32(oracle_ssz.FULU_FORK_VERSION),
    }
    for key, value in expected.items():
        if spec.get(key) != value:
            fail(f"beacon node reports {key} {spec.get(key)}, the oracle assumes {value}")
    if genesis.get("genesis_time") != str(oracle_ssz.GENESIS_TIME):
        fail(f"beacon node reports genesis time {genesis.get('genesis_time')}")
    if genesis.get("genesis_validators_root") != hex32(oracle_ssz.MAINNET_GENESIS_VALIDATORS_ROOT):
        fail("beacon node is not on mainnet")
    return int(beacon_get("/eth/v1/config/deposit_contract")["data"]["chain_id"])


def stage_and_commit(fixtures, rows):
    for fixture in fixtures:
        if not capture_getproof.NAME_PATTERN.fullmatch(fixture["name"]):
            fail(f"refusing to write a fixture named {fixture['name']!r}")
    with tempfile.TemporaryDirectory() as scratch:
        scratch_dir = pathlib.Path(scratch)
        for fixture in fixtures:
            (scratch_dir / f"{fixture['name']}.json").write_text(json.dumps(fixture))
        for fixture in fixtures:
            if fixture["kind"] in oracle_ssz.BEACON_KINDS:
                try:
                    for line in oracle_ssz.check_fixture(fixture, scratch_dir):
                        print(f"  {fixture['name']}: {line}")
                except oracle_ssz.CheckError as e:
                    fail(f"refusing to write: oracle rejected {fixture['name']}: {e}")
    capture_getproof.commit(fixtures, rows)


def check_positions(cls, keys_by_field, oracle_by_field):
    for field, keys in keys_by_field.items():
        if type_gindex(cls, keys) != oracle_by_field[field]:
            fail(f"position of {field}: remerkleable {type_gindex(cls, keys)}, oracle {oracle_by_field[field]}")


def chain():
    chain_id_beacon = check_network()
    url = env("RPC_URL")
    head = int(capture_getproof.rpc(url, "eth_blockNumber", []), 16)
    number = head - 2
    header = capture_getproof.block_header(url, hex(number))
    child = capture_getproof.block_header(url, hex(number + 1))
    if child["parentHash"] != header["hash"]:
        fail("block N+1 does not extend block N; the head moved during capture, run again")
    beacon_root = child["parentBeaconBlockRoot"]
    response = beacon_get(f"/eth/v2/beacon/blocks/{beacon_root}")
    check_version(response)
    block = t.BeaconBlock.from_obj(response["data"]["message"])
    if hex32(block.hash_tree_root()) != beacon_root:
        fail("computed beacon block root differs from parentBeaconBlockRoot")
    payload = block.body.execution_payload
    if int(payload.block_number) != number:
        fail(f"payload block number {int(payload.block_number)}, expected {number}")
    if hex32(payload.state_root) != header["stateRoot"] or hex32(payload.block_hash) != header["hash"]:
        fail("payload state_root or block_hash differs from execution block N")
    fields = {f"execution_payload.{f}": f for f in ("state_root", "block_number", "block_hash")}
    oracle_positions = {name: oracle_ssz.payload_gindex(f) for name, f in fields.items()}
    check_positions(t.BeaconBlock, {name: ["body", "execution_payload", f] for name, f in fields.items()}, oracle_positions)
    proofs = []
    for name, gindex in oracle_positions.items():
        leaf, siblings = branch(block.get_backing(), gindex)
        proofs.append(proof_json(name, gindex, leaf, siblings))
    beacon_header = t.BeaconBlockHeader(
        slot=block.slot,
        proposer_index=block.proposer_index,
        parent_root=block.parent_root,
        state_root=block.state_root,
        body_root=block.body.hash_tree_root(),
    )
    storage = [
        capture_getproof.build_fixture(
            url, "chain_storage_usdc", USDC, header, [capture_getproof.slot_word(s) for s in ("0", ABSENT)]
        ),
        capture_getproof.build_fixture(
            url, "chain_storage_weth", WETH, header, [capture_getproof.slot_word(s) for s in ("0", "1", "2")]
        ),
        capture_getproof.build_fixture(url, "chain_account_absent", ABSENT, header, []),
    ]
    usdc = oracle_mpt.analyze(storage[0])
    if not usdc["slots"][0]["present"] or usdc["slots"][1]["present"]:
        fail("USDC slot 0 must be set and slot 0xa55a70ff unset at block N")
    if oracle_mpt.analyze(storage[2])["present"]:
        fail(f"{ABSENT} holds an account at block N")
    if any(f["chainId"] != chain_id_beacon for f in storage):
        fail("execution chain id differs from the beacon deposit chain id")
    beacon = {
        "name": "chain_beacon",
        "kind": "beacon_chain",
        "consensusVersion": oracle_ssz.CONSENSUS_VERSION,
        "beacon": {"blockRoot": beacon_root, "header": header_json(beacon_header)},
        "execution": {"header": header, "childHeader": child, "mptFixtures": [f["name"] for f in storage]},
        "proofs": proofs,
    }
    rows = [capture_getproof.fixture_row(f, "capture_beacon.py chain") for f in storage]
    rows.append(
        capture_getproof.readme_row(
            "chain_beacon", "beacon_chain", chain_id_beacon, f"slot {int(block.slot)}", beacon_root,
            header["stateRoot"], "capture_beacon.py chain",
        )
    )
    stage_and_commit(storage + [beacon], rows)


def validator(state_path, index_text, fixture_name):
    if not DECIMAL_PATTERN.fullmatch(index_text):
        fail(f"validator index must be a decimal number: {index_text}")
    if not VALIDATOR_NAME_PATTERN.fullmatch(fixture_name):
        fail(f"fixture name must look like validator_<word>: {fixture_name}")
    index = int(index_text)
    chain_id = check_network()
    url = env("RPC_URL")
    state = t.BeaconState.decode_bytes(pathlib.Path(state_path).read_bytes())
    if index >= len(state.validators):
        fail(f"validator {index} does not exist; the registry has {len(state.validators)}")
    if bytes(state.genesis_validators_root) != oracle_ssz.MAINNET_GENESIS_VALIDATORS_ROOT:
        fail("state is not a mainnet state")
    if bytes(state.fork.current_version) != oracle_ssz.FULU_FORK_VERSION:
        fail(f"state fork version {hex32(state.fork.current_version)} is not Fulu")
    state_root = hex32(state.hash_tree_root())
    slot = int(state.slot)
    response = beacon_get(f"/eth/v1/beacon/headers/{slot}")
    if response.get("finalized") is not True or response["data"].get("canonical") is not True:
        fail(f"the block at slot {slot} is not reported finalized and canonical")
    message = response["data"]["header"]["message"]
    if message["state_root"] != state_root:
        fail(f"computed state root {state_root} differs from the header's {message['state_root']}")
    beacon_root = response["data"]["root"]
    beacon_header = t.BeaconBlockHeader.from_obj(message)
    if hex32(beacon_header.hash_tree_root()) != beacon_root:
        fail("computed header root differs from the reported block root")
    payload = state.latest_execution_payload_header
    number = int(payload.block_number)
    header = capture_getproof.block_header(url, hex(number))
    child = capture_getproof.block_header(url, hex(number + 1))
    if header["hash"] != hex32(payload.block_hash) or child["parentHash"] != header["hash"]:
        fail("execution blocks do not match the state's latest payload")
    if child["parentBeaconBlockRoot"] != beacon_root:
        fail("the child execution block does not name this beacon block")
    header_position = oracle_ssz.field_gindex(oracle_ssz.HEADER_FIELDS, oracle_ssz.HEADER_STATE_ROOT)
    if type_gindex(t.BeaconBlockHeader, ["state_root"]) != header_position:
        fail("position of header.state_root disagrees between remerkleable and the oracle")
    header_leaf, header_siblings = branch(beacon_header.get_backing(), header_position)
    if hex32(header_leaf) != state_root:
        fail("header branch does not end at the state root")
    record = state.validators[index]
    prefix = f"validators[{index}]."
    in_state = {f"validators[{index}]": oracle_ssz.validator_element_gindex(index)}
    in_state.update({prefix + f: oracle_ssz.validator_state_gindex(index, f) for f in ("pubkey", "withdrawal_credentials", "effective_balance")})
    in_state["genesis_validators_root"] = oracle_ssz.state_gindex("genesis_validators_root")
    in_state["fork.current_version"] = oracle_ssz.state_gindex("fork.current_version")
    in_state["latest_execution_payload_header.block_hash"] = oracle_ssz.state_gindex(
        "latest_execution_payload_header.block_hash"
    )
    type_keys = {f"validators[{index}]": ["validators", index]}
    type_keys.update({prefix + f: ["validators", index, f] for f in ("pubkey", "withdrawal_credentials", "effective_balance")})
    type_keys["genesis_validators_root"] = ["genesis_validators_root"]
    type_keys["fork.current_version"] = ["fork", "current_version"]
    type_keys["latest_execution_payload_header.block_hash"] = ["latest_execution_payload_header", "block_hash"]
    check_positions(t.BeaconState, type_keys, in_state)
    proofs = []
    for name, gindex in in_state.items():
        leaf, siblings = branch(state.get_backing(), gindex)
        proofs.append(proof_json(name, oracle_ssz.from_block_root(gindex), leaf, siblings + header_siblings))
    fixture = {
        "name": fixture_name,
        "kind": "beacon_validator",
        "consensusVersion": oracle_ssz.CONSENSUS_VERSION,
        "beacon": {"blockRoot": beacon_root, "header": header_json(beacon_header)},
        "execution": {"header": header, "childHeader": child},
        "capture": {"finalized": True, "canonical": True},
        "validatorIndex": str(index),
        "validator": {
            "pubkey": "0x" + bytes(record.pubkey).hex(),
            "withdrawal_credentials": hex32(record.withdrawal_credentials),
            "effective_balance": str(int(record.effective_balance)),
            "slashed": bool(record.slashed),
            **{name: str(int(getattr(record, name))) for name in oracle_ssz.VALIDATOR_EPOCHS},
        },
        "proofs": proofs,
    }
    row = capture_getproof.readme_row(
        fixture_name, "beacon_validator", chain_id, f"slot {slot}", beacon_root, state_root,
        f"capture_beacon.py validator <finalized state at slot {slot}> {index} {fixture_name}",
    )
    stage_and_commit([fixture], [row])


def main(argv):
    if len(argv) == 2 and argv[1] == "chain":
        chain()
    elif len(argv) == 5 and argv[1] == "validator":
        validator(argv[2], argv[3], argv[4])
    else:
        fail(__doc__)


if __name__ == "__main__":
    main(sys.argv)
