"""Capture beacon chain proofs as fixtures.

usage: capture_beacon.py chain
       capture_beacon.py validator <state.ssz> <validator index>

chain reads RPC_URL (execution JSON-RPC) and BEACON_URL (beacon API). It picks
execution block N two blocks behind the head, reads block N+1, and fetches the
beacon block named by N+1's parentBeaconBlockRoot, which is the block whose
execution payload is N. It writes fixtures/chain_beacon.json with proofs of the
payload's state_root, block_number and block_hash against the beacon block
root, and captures eth_getProof fixtures at block N as chain_storage_usdc and
chain_storage_weth through capture_getproof.py.

validator reads BEACON_URL and a finalized BeaconState in SSZ. It writes
fixtures/validator_beacon.json with proofs of the validator's
withdrawal_credentials and effective_balance against the root of the beacon
block at the state's slot.

Nothing is written unless every computed root equals the root the chain
reports and oracle_ssz.py accepts the fixture. Requires remerkleable 0.1.28
and pycryptodome.
"""

import datetime
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import capture_getproof
import oracle_ssz
import ssz_types as t

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
CONSENSUS_VERSION = "fulu"


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
            return json.load(response)
    except urllib.error.HTTPError as e:
        fail(f"beacon {path}: HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        fail(f"beacon {path}: {e.reason}")


def execution_header(tag):
    header = capture_getproof.rpc(env("RPC_URL"), "eth_getBlockByNumber", [tag, False])
    if header is None:
        fail(f"execution block not found: {tag}")
    for key in ("transactions", "withdrawals", "uncles"):
        header.pop(key, None)
    return header


def hex32(data):
    return "0x" + bytes(data).hex()


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


def readme_row(name, kind, block, block_hash, state_root, command):
    captured = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    return f"| {name} | {kind} | 1 | {block} | {block_hash} | {state_root} | {captured} | `{command}` |"


def write_fixture(name, fixture, row):
    try:
        lines = oracle_ssz.check_fixture(fixture)
    except Exception as e:
        fail(f"refusing to write {name}: oracle rejected it: {e}")
    FIXTURES.mkdir(exist_ok=True)
    path = FIXTURES / f"{name}.json"
    path.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")
    rows = [r for r in capture_getproof.readme_rows() if r.split("|")[1].strip() != name]
    capture_getproof.write_readme(rows + [row])
    print(path)
    for line in lines:
        print(f"  {line}")


def chain():
    head = int(capture_getproof.rpc(env("RPC_URL"), "eth_blockNumber", []), 16)
    number = head - 2
    header = execution_header(hex(number))
    child = execution_header(hex(number + 1))
    if child["parentHash"] != header["hash"]:
        fail("block N+1 does not extend block N; the head moved during capture, run again")
    beacon_root = child["parentBeaconBlockRoot"]
    response = beacon_get(f"/eth/v2/beacon/blocks/{beacon_root}")
    if response.get("version") != CONSENSUS_VERSION:
        fail(f"beacon block version {response.get('version')}, this tool handles {CONSENSUS_VERSION}")
    block = t.BeaconBlock.from_obj(response["data"]["message"])
    if hex32(block.hash_tree_root()) != beacon_root:
        fail("computed beacon block root differs from parentBeaconBlockRoot")
    payload = block.body.execution_payload
    if int(payload.block_number) != number:
        fail(f"payload block number {int(payload.block_number)}, expected {number}")
    if hex32(payload.state_root) != header["stateRoot"] or hex32(payload.block_hash) != header["hash"]:
        fail("payload state_root or block_hash differs from execution block N")
    beacon_header = t.BeaconBlockHeader(
        slot=block.slot,
        proposer_index=block.proposer_index,
        parent_root=block.parent_root,
        state_root=block.state_root,
        body_root=block.body.hash_tree_root(),
    )
    proofs = []
    for field in ("state_root", "block_number", "block_hash"):
        gindex = oracle_ssz.payload_gindex(field)
        leaf, siblings = branch(block.get_backing(), gindex)
        proofs.append(proof_json(f"execution_payload.{field}", gindex, leaf, siblings))
    fixture = {
        "name": "chain_beacon",
        "kind": "beacon_chain",
        "consensusVersion": CONSENSUS_VERSION,
        "beacon": {"blockRoot": beacon_root, "header": header_json(beacon_header)},
        "execution": {"header": header, "childHeader": child, "mptFixtures": ["chain_storage_usdc", "chain_storage_weth"]},
        "proofs": proofs,
    }
    try:
        oracle_ssz.check_fixture(fixture)
    except Exception as e:
        fail(f"refusing to capture: oracle rejected the beacon proofs: {e}")
    for name, address, slots in (("chain_storage_usdc", USDC, ["0"]), ("chain_storage_weth", WETH, ["0", "1", "2"])):
        capture_getproof.capture([name, address, str(number), *slots])
        written = json.loads((FIXTURES / f"{name}.json").read_text())
        if written["header"]["hash"] != header["hash"]:
            fail(f"{name} was captured at a different block hash; run again")
    row = readme_row("chain_beacon", "beacon_chain", number, header["hash"], header["stateRoot"], "capture_beacon.py chain")
    write_fixture("chain_beacon", fixture, row)


def validator(state_path, index_text):
    if not index_text.isdigit():
        fail(f"validator index must be a decimal number: {index_text}")
    index = int(index_text)
    state = t.BeaconState.decode_bytes(pathlib.Path(state_path).read_bytes())
    if index >= len(state.validators):
        fail(f"validator {index} does not exist; the registry has {len(state.validators)}")
    state_root = hex32(state.hash_tree_root())
    slot = int(state.slot)
    response = beacon_get(f"/eth/v1/beacon/headers/{slot}")
    header = response["data"]["header"]["message"]
    if int(header["slot"]) != slot:
        fail(f"no beacon block at slot {slot}; the state is not a block's post-state")
    if header["state_root"] != state_root:
        fail(f"computed state root {state_root} differs from the header's {header['state_root']}")
    beacon_root = response["data"]["root"]
    beacon_header = t.BeaconBlockHeader.from_obj(header)
    if hex32(beacon_header.hash_tree_root()) != beacon_root:
        fail("computed header root differs from the reported block root")
    record = state.validators[index]
    header_leaf, header_siblings = branch(beacon_header.get_backing(), 11)
    if hex32(header_leaf) != state_root:
        fail("header branch does not end at the state root")
    proofs = []
    for field, local in (("withdrawal_credentials", 1), ("effective_balance", 2)):
        in_state = (((64 + 11) * 2) << 40 | index) * 8 + local
        leaf, siblings = branch(state.get_backing(), in_state)
        gindex = oracle_ssz.validator_gindex(index, field)
        if gindex != oracle_ssz.concat(11, in_state):
            fail(f"gindex disagreement for {field}")
        proofs.append(proof_json(f"validators[{index}].{field}", gindex, leaf, siblings + header_siblings))
    fixture = {
        "name": "validator_beacon",
        "kind": "beacon_validator",
        "consensusVersion": CONSENSUS_VERSION,
        "beacon": {"blockRoot": beacon_root, "header": header_json(beacon_header)},
        "validatorIndex": str(index),
        "validator": {
            "pubkey": hex32(record.pubkey),
            "withdrawal_credentials": hex32(record.withdrawal_credentials),
            "effective_balance": str(int(record.effective_balance)),
        },
        "proofs": proofs,
    }
    row = readme_row(
        "validator_beacon", "beacon_validator", f"slot {slot}", beacon_root, state_root,
        f"capture_beacon.py validator <finalized state at slot {slot}> {index}",
    )
    write_fixture("validator_beacon", fixture, row)


def main(argv):
    if len(argv) == 2 and argv[1] == "chain":
        chain()
    elif len(argv) == 4 and argv[1] == "validator":
        validator(argv[2], argv[3])
    else:
        fail(__doc__)


if __name__ == "__main__":
    main(sys.argv)
