"""Capture a Gloas frame fixture from the bogota-devnet-2 frames devnet.

usage, with the consensus-specs virtualenv python so the Gloas spec is importable:

    <specs>/.venv/bin/python -I tools/capture_frame.py <specs> fixtures/frame_gloas.json

The fixture anchors an execution storage fact to a beacon block root the way
the frame gate does on the devnet: beacon root, recomputed header, the Gloas
state's latest_block_hash proven by an SSZ branch, the execution header RLP
whose keccak equals that hash, and a Merkle-Patricia proof of the EIP-4788
ring buffer's own storage under the header's state root. The proven slots are
self-checking: the timestamp slot must hold the block's timestamp and the
root slot must hold the block's parent beacon root.

Every branch is verified twice before it is written: once with the spec's
own machinery and once with plain hashing that shares no code with it. The
fixture records the spec commit and the devnet endpoints, because the devnet
is temporary; regenerating against a successor devnet is one rerun.
"""

import json
import pathlib
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from oracle_mpt import check_header, keccak256, to_int, hex_bytes, walk, rlp_decode

import hashlib

BEACON = "https://beacon.bogota-devnet-2.ethpandaops.io"
RPC = "https://rpc.bogota-devnet-2.ethpandaops.io"
BEACON_ROOTS = "0x000f3df6d732807ef1319fb7b8bb8522d0beac02"
HISTORY_BUFFER_LENGTH = 8191
STATE_LATEST_BLOCK_HASH_GINDEX = 2947
LATEST_BLOCK_HASH_GINDEX = 23427


def http_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "assay-capture"})
    with urllib.request.urlopen(request, timeout=30) as reply:
        return json.load(reply)


def http_bytes(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "assay-capture", "Accept": "application/octet-stream"},
    )
    with urllib.request.urlopen(request, timeout=120) as reply:
        return reply.read()


def rpc_call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    request = urllib.request.Request(
        RPC,
        data=body.encode(),
        headers={"Content-Type": "application/json", "User-Agent": "assay-capture"},
    )
    with urllib.request.urlopen(request, timeout=30) as reply:
        answer = json.load(reply)
    if "error" in answer:
        raise SystemExit(f"error: {method} failed: {answer['error']}")
    return answer["result"]


def sha256_walk(leaf, gindex, branch):
    node = leaf
    index = gindex
    for sibling in branch:
        if index & 1:
            node = hashlib.sha256(sibling + node).digest()
        else:
            node = hashlib.sha256(node + sibling).digest()
        index >>= 1
    if index != 1:
        raise SystemExit("error: branch length does not match the gindex depth")
    return node


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    specs = pathlib.Path(argv[1])
    out = pathlib.Path(argv[2])

    sys.path.insert(0, str(specs / "tests" / "core" / "pyspec"))
    from eth_consensus_specs.gloas import mainnet as spec

    spec_commit = subprocess.run(
        ["git", "-C", str(specs), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    finalized = http_json(f"{BEACON}/eth/v1/beacon/headers/finalized")["data"]
    header = finalized["header"]["message"]
    slot = int(header["slot"])
    beacon_root = finalized["root"]

    state = spec.BeaconState.decode_bytes(
        http_bytes(f"{BEACON}/eth/v2/debug/beacon/states/{slot}")
    )
    if int(state.slot) != slot:
        raise SystemExit(f"error: state is for slot {int(state.slot)}, header is {slot}")
    state_root = bytes(state.hash_tree_root())
    if state_root != hex_bytes(header["state_root"], 32):
        raise SystemExit("error: computed state root differs from the header")

    gindex = spec.get_generalized_index(spec.BeaconState, "latest_block_hash")
    if int(gindex) != STATE_LATEST_BLOCK_HASH_GINDEX:
        raise SystemExit(
            f"error: latest_block_hash gindex is {int(gindex)}, expected {STATE_LATEST_BLOCK_HASH_GINDEX}"
        )
    state_branch = [bytes(node) for node in spec.compute_merkle_proof(state, gindex)]
    latest_block_hash = bytes(state.latest_block_hash)
    if sha256_walk(latest_block_hash, int(gindex), state_branch) != state_root:
        raise SystemExit("error: the latest_block_hash branch does not reconstruct the state root")

    header_root = bytes(
        spec.BeaconBlockHeader(
            slot=slot,
            proposer_index=int(header["proposer_index"]),
            parent_root=hex_bytes(header["parent_root"], 32),
            state_root=state_root,
            body_root=hex_bytes(header["body_root"], 32),
        ).hash_tree_root()
    )
    if header_root != hex_bytes(beacon_root, 32):
        raise SystemExit("error: recomputed header root differs from the API's block root")

    def chunk(value):
        return value.to_bytes(8, "little") + b"\x00" * 24

    slot_pair = hashlib.sha256(chunk(slot) + chunk(int(header["proposer_index"]))).digest()
    body_half = hashlib.sha256(
        hashlib.sha256(hex_bytes(header["body_root"], 32) + b"\x00" * 32).digest()
        + hashlib.sha256(b"\x00" * 64).digest()
    ).digest()
    branch = state_branch + [hex_bytes(header["parent_root"], 32), slot_pair, body_half]
    if sha256_walk(latest_block_hash, LATEST_BLOCK_HASH_GINDEX, branch) != header_root:
        raise SystemExit("error: the full branch does not reconstruct the beacon root")

    block = rpc_call("eth_getBlockByHash", ["0x" + latest_block_hash.hex(), False])
    if block is None:
        raise SystemExit("error: execution block for latest_block_hash not found")
    header_rlp = check_header(block)

    timestamp = to_int(block["timestamp"])
    timestamp_slot = timestamp % HISTORY_BUFFER_LENGTH
    root_slot = timestamp_slot + HISTORY_BUFFER_LENGTH
    proof = rpc_call(
        "eth_getProof",
        [BEACON_ROOTS, [hex(timestamp_slot), hex(root_slot)], block["number"]],
    )

    exec_state_root = hex_bytes(block["stateRoot"], 32)
    account_nodes = [hex_bytes(node) for node in proof["accountProof"]]
    account_rlp = walk(exec_state_root, keccak256(hex_bytes(BEACON_ROOTS, 20)), account_nodes)
    if account_rlp is None:
        raise SystemExit("error: the 4788 account is absent from the proof")
    storage_root = rlp_decode(account_rlp)[2]

    values = {}
    for entry in proof["storageProof"]:
        nodes = [hex_bytes(node) for node in entry["proof"]]
        value_rlp = walk(storage_root, keccak256(to_int(entry["key"]).to_bytes(32, "big")), nodes)
        values[to_int(entry["key"])] = (
            0 if value_rlp is None else int.from_bytes(rlp_decode(value_rlp), "big")
        )

    if values[timestamp_slot] != timestamp:
        raise SystemExit(
            f"error: the ring buffer timestamp slot holds {values[timestamp_slot]}, block timestamp is {timestamp}"
        )
    parent_beacon_root = to_int(block["parentBeaconBlockRoot"])
    if values[root_slot] != parent_beacon_root:
        raise SystemExit("error: the ring buffer root slot does not hold the parent beacon root")

    fixture = {
        "name": "frame_gloas",
        "kind": "frame_gloas",
        "network": "bogota-devnet-2",
        "chainId": to_int(rpc_call("eth_chainId", [])),
        "specCommit": spec_commit,
        "fork": str(spec.fork),
        "endpoints": {"beacon": BEACON, "rpc": RPC},
        "beaconRoot": beacon_root,
        "beaconHeader": {
            "slot": str(slot),
            "proposer_index": header["proposer_index"],
            "parent_root": header["parent_root"],
            "state_root": header["state_root"],
            "body_root": header["body_root"],
        },
        "latestBlockHashGindex": str(LATEST_BLOCK_HASH_GINDEX),
        "latestBlockHash": "0x" + latest_block_hash.hex(),
        "latestBlockHashBranch": ["0x" + node.hex() for node in branch],
        "executionHeaderRlp": "0x" + header_rlp.hex(),
        "executionHeader": {
            "number": block["number"],
            "timestamp": block["timestamp"],
            "stateRoot": block["stateRoot"],
            "parentBeaconBlockRoot": block["parentBeaconBlockRoot"],
        },
        "account": BEACON_ROOTS,
        "timestampSlot": hex(timestamp_slot),
        "rootSlot": hex(root_slot),
        "proof": proof,
    }
    out.write_text(json.dumps(fixture, indent=1) + "\n")
    print(
        f"wrote {out}: beacon slot {slot}, execution block {to_int(block['number'])}, spec {spec_commit[:12]}"
    )


if __name__ == "__main__":
    main(sys.argv)
