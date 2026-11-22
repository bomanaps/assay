"""Drive the frame gate on the bogota-devnet-2 frames devnet.

usage:

    python3 -I tools/frame_devnet.py key <state-dir>
    python3 -I tools/frame_devnet.py deploy <state-dir> <gate-bin>
    <specs-venv-python> -I tools/frame_devnet.py send <state-dir> <specs-checkout>
    python3 -I tools/frame_devnet.py status <state-dir>

`key` makes a throwaway devnet key and prints the address to fund at the
devnet faucet. The key is for this disposable test network only; point the
state directory outside the repository and never reuse the key anywhere real.

`deploy` sends three contracts with cast: a tiny storage target whose slot 0
holds 42, the Fe FrameGate watching that slot, and the pay-frame shim
assembled around the gate's address, then funds the shim so it can pay.

`send` captures a fresh anchor from the devnet, builds the type 0x06 frame
transaction [only_verify, pay] whose pay frame carries the full proof, signs
it per the EIP-8141 signature hash, and submits it. The transaction's gas is
paid by the shim, and only because the proof verified.
"""

import json
import pathlib
import secrets
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from oracle_mpt import (
    keccak256,
    rlp_encode_bytes,
    rlp_encode_list,
    rlp_encode_quantity,
    to_int,
    hex_bytes,
)
import frame_shim

RPC = "https://rpc.bogota-devnet-2.ethpandaops.io"
BEACON = "https://beacon.bogota-devnet-2.ethpandaops.io"
FAUCET = "https://faucet.bogota-devnet-2.ethpandaops.io"
EXPLORER = "https://dora.bogota-devnet-2.ethpandaops.io"
BEACON_ROOTS = "0x000f3df6d732807ef1319fb7b8bb8522d0beac02"

FRAME_TX_TYPE = 0x06
MODE_VERIFY = 1
FLAGS_APPROVE_EXECUTION = 2
FLAGS_APPROVE_PAYMENT = 1
SCHEME_SECP256K1 = 1

TARGET_INITCODE = bytes.fromhex("602a5f555f5ff3")
TARGET_SLOT = 0
TARGET_VALUE = 42
VALUE_FLOOR = 1
GLOAS_FIRST_SLOT = 0
GATE_END_SLOT = 10_000_000

ONLY_VERIFY_GAS = 5_000
PAY_EXECUTION_GAS = 290_000
PAY_STATE_GAS = 10_000
MAX_FEE_WEI = 5 * 10**17
MAX_PRIORITY_FEE = 10**9

CHECK_PAY_SIGNATURE = (
    "checkPay(uint64,(uint64,uint64,bytes32,bytes32,bytes32),"
    "bytes32,bytes32[],bytes,bytes[],bytes[])"
)


def rpc_call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    request = urllib.request.Request(
        RPC,
        data=body.encode(),
        headers={"Content-Type": "application/json", "User-Agent": "assay-devnet"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as reply:
            answer = json.load(reply)
    except urllib.error.HTTPError as failure:
        detail = failure.read().decode(errors="replace")[:500]
        raise SystemExit(f"error: {method} answered HTTP {failure.code}: {detail}")
    if "error" in answer:
        raise SystemExit(f"error: {method} failed: {answer['error']}")
    return answer["result"]


def load_state(state_dir):
    path = state_dir / "devnet.json"
    if not path.exists():
        raise SystemExit(f"error: {path} does not exist; run the key step first")
    return json.loads(path.read_text())


def save_state(state_dir, state):
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "devnet.json").write_text(json.dumps(state, indent=1) + "\n")


def make_key(state_dir):
    from coincurve import PrivateKey

    key = PrivateKey(secrets.token_bytes(32))
    public = key.public_key.format(compressed=False)[1:]
    address = "0x" + keccak256(public)[12:].hex()
    save_state(state_dir, {"key": key.to_hex(), "address": address})
    print(f"devnet address: {address}")
    print(f"fund it at {FAUCET} (the faucet needs a browser for its captcha)")
    print("this key is throwaway devnet material; it never leaves this machine")


def cast(state, arguments):
    command = (
        ["cast", arguments[0], "--rpc-url", RPC, "--private-key", state["key"]]
        + arguments[1:]
    )
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"error: cast failed: {result.stderr.strip()}")
    return result.stdout.strip()


def deployed_address(send_output):
    for line in send_output.splitlines():
        if line.startswith("contractAddress"):
            return line.split()[-1]
    raise SystemExit(f"error: no contractAddress in cast output:\n{send_output}")


def deploy(state_dir, gate_bin):
    state = load_state(state_dir)
    balance = int(rpc_call("eth_getBalance", [state["address"], "latest"]), 16)
    if balance < 10**18:
        raise SystemExit(
            f"error: {state['address']} holds {balance} wei; fund it at {FAUCET} first"
        )

    target_out = cast(state, ["send", "--create", "0x" + TARGET_INITCODE.hex()])
    target = deployed_address(target_out)
    print(f"storage target: {target}")

    constructor = (
        hex_bytes(BEACON_ROOTS, 20).rjust(32, b"\x00")
        + hex_bytes(target.lower(), 20).rjust(32, b"\x00")
        + TARGET_SLOT.to_bytes(32, "big")
        + VALUE_FLOOR.to_bytes(32, "big")
        + GLOAS_FIRST_SLOT.to_bytes(32, "big")
        + GATE_END_SLOT.to_bytes(32, "big")
    )
    gate_code = gate_bin.read_text().strip().removeprefix("0x")
    gate_out = cast(state, ["send", "--create", "0x" + gate_code + constructor.hex()])
    gate = deployed_address(gate_out)
    print(f"frame gate: {gate}")

    runtime, _ = frame_shim.assemble(hex_bytes(gate.lower(), 20))
    shim_out = cast(state, ["send", "--create", "0x" + frame_shim.initcode(runtime).hex()])
    shim = deployed_address(shim_out)
    print(f"pay shim: {shim}")

    cast(state, ["send", shim, "--value", "2ether"])
    print("shim funded with 2 devnet ether")

    state.update({"target": target, "gate": gate, "shim": shim})
    save_state(state_dir, state)


def abi_word(value):
    if isinstance(value, bytes):
        return value.rjust(32, b"\x00")
    return value.to_bytes(32, "big")


def abi_bytes(data):
    padded = data + b"\x00" * (-len(data) % 32)
    return abi_word(len(data)) + padded


def abi_bytes_array(items):
    head = abi_word(len(items))
    offsets, tail = b"", b""
    for item in items:
        offsets += abi_word(32 * len(items) + len(tail))
        tail += abi_bytes(item)
    return head + offsets + tail


def check_pay_calldata(capture):
    selector = keccak256(CHECK_PAY_SIGNATURE.encode())[:4]
    header = capture["beaconHeader"]
    static = [
        abi_word(capture["timestamp"]),
        abi_word(int(header["slot"])),
        abi_word(int(header["proposer_index"])),
        abi_word(hex_bytes(header["parent_root"], 32)),
        abi_word(hex_bytes(header["state_root"], 32)),
        abi_word(hex_bytes(header["body_root"], 32)),
        abi_word(hex_bytes(capture["latestBlockHash"], 32)),
    ]
    branch = b"".join(
        abi_word(hex_bytes(node, 32)) for node in capture["latestBlockHashBranch"]
    )
    branch = abi_word(len(capture["latestBlockHashBranch"])) + branch
    header_rlp = hex_bytes(capture["executionHeaderRlp"])
    account_nodes = [hex_bytes(node) for node in capture["accountNodes"]]
    storage_nodes = [hex_bytes(node) for node in capture["storageNodes"]]

    tails = [branch, abi_bytes(header_rlp), abi_bytes_array(account_nodes), abi_bytes_array(storage_nodes)]
    head_size = 32 * (len(static) + len(tails))
    heads, body = list(static), b""
    for tail in tails:
        heads.append(abi_word(head_size + len(body)))
        body += tail
    return selector + b"".join(heads) + body


def capture_anchor(state, specs):
    sys.path.insert(0, str(pathlib.Path(specs) / "tests" / "core" / "pyspec"))
    from eth_consensus_specs.gloas import mainnet as spec
    import capture_frame

    head = int(rpc_call("eth_blockNumber", []), 16)
    block = rpc_call("eth_getBlockByNumber", [hex(head - 8), False])
    timestamp = to_int(block["timestamp"])
    anchor_root = block["parentBeaconBlockRoot"]

    beacon_header = capture_frame.http_json(f"{BEACON}/eth/v1/beacon/headers/{anchor_root}")[
        "data"
    ]["header"]["message"]
    slot = int(beacon_header["slot"])
    state_ssz = capture_frame.http_bytes(f"{BEACON}/eth/v2/debug/beacon/states/{slot}")
    beacon_state = spec.BeaconState.decode_bytes(state_ssz)
    state_root = bytes(beacon_state.hash_tree_root())
    if state_root != hex_bytes(beacon_header["state_root"], 32):
        raise SystemExit("error: computed state root differs from the devnet header")

    gindex = spec.get_generalized_index(spec.BeaconState, "latest_block_hash")
    state_branch = [bytes(node) for node in spec.compute_merkle_proof(beacon_state, gindex)]
    latest_block_hash = bytes(beacon_state.latest_block_hash)

    def chunk(value):
        return value.to_bytes(8, "little") + b"\x00" * 24

    import hashlib

    slot_pair = hashlib.sha256(
        chunk(slot) + chunk(int(beacon_header["proposer_index"]))
    ).digest()
    body_half = hashlib.sha256(
        hashlib.sha256(hex_bytes(beacon_header["body_root"], 32) + b"\x00" * 32).digest()
        + hashlib.sha256(b"\x00" * 64).digest()
    ).digest()
    branch = state_branch + [
        hex_bytes(beacon_header["parent_root"], 32),
        slot_pair,
        body_half,
    ]
    if capture_frame.sha256_walk(
        latest_block_hash, capture_frame.LATEST_BLOCK_HASH_GINDEX, branch
    ) != hex_bytes(anchor_root, 32):
        raise SystemExit("error: the anchor branch does not reconstruct the beacon root")

    proven_block = rpc_call("eth_getBlockByHash", ["0x" + latest_block_hash.hex(), False])
    from oracle_mpt import check_header

    header_rlp = check_header(proven_block)

    proof = rpc_call(
        "eth_getProof", [state["target"], [hex(TARGET_SLOT)], proven_block["number"]]
    )
    slot_proof = proof["storageProof"][0]
    if to_int(slot_proof["value"]) != TARGET_VALUE:
        raise SystemExit(
            f"error: the target slot holds {slot_proof['value']}, expected {TARGET_VALUE}"
        )

    return {
        "timestamp": timestamp,
        "beaconHeader": beacon_header,
        "latestBlockHash": "0x" + latest_block_hash.hex(),
        "latestBlockHashBranch": ["0x" + node.hex() for node in branch],
        "executionHeaderRlp": "0x" + header_rlp.hex(),
        "accountNodes": proof["accountProof"],
        "storageNodes": slot_proof["proof"],
    }


def encode_frames(shim, calldata):
    only_verify = [
        rlp_encode_quantity(MODE_VERIFY),
        rlp_encode_quantity(FLAGS_APPROVE_EXECUTION),
        rlp_encode_bytes(b""),
        rlp_encode_list([rlp_encode_quantity(ONLY_VERIFY_GAS), rlp_encode_quantity(0)]),
        rlp_encode_quantity(0),
        rlp_encode_bytes(b""),
    ]
    pay = [
        rlp_encode_quantity(MODE_VERIFY),
        rlp_encode_quantity(FLAGS_APPROVE_PAYMENT),
        rlp_encode_bytes(hex_bytes(shim.lower(), 20)),
        rlp_encode_list(
            [rlp_encode_quantity(PAY_EXECUTION_GAS), rlp_encode_quantity(PAY_STATE_GAS)]
        ),
        rlp_encode_quantity(0),
        rlp_encode_bytes(calldata),
    ]
    return rlp_encode_list([rlp_encode_list(only_verify), rlp_encode_list(pay)])


def frame_tx_payload(state, nonce, frames, signature_field):
    """The devnet runs EIP-8250, so the payload carries nonce_keys and
    nonce_seq in place of the plain nonce; an empty key list selects the
    ordinary account nonce."""
    signature = [
        rlp_encode_quantity(SCHEME_SECP256K1),
        rlp_encode_bytes(b""),
        rlp_encode_bytes(b""),
        signature_field,
    ]
    fields = [
        rlp_encode_quantity(to_int(rpc_call("eth_chainId", []))),
        rlp_encode_list([]),
        rlp_encode_quantity(nonce),
        rlp_encode_bytes(hex_bytes(state["address"].lower(), 20)),
        frames,
        rlp_encode_list([rlp_encode_list(signature)]),
        rlp_encode_list(
            [rlp_encode_quantity(MAX_FEE_WEI), rlp_encode_quantity(MAX_PRIORITY_FEE)]
        ),
        rlp_encode_list([]),
    ]
    return rlp_encode_list(fields)


def send(state_dir, specs):
    from coincurve import PrivateKey

    state = load_state(state_dir)
    for needed in ("target", "gate", "shim"):
        if needed not in state:
            raise SystemExit(f"error: no {needed} in the state file; run deploy first")

    capture = capture_anchor(state, specs)
    calldata = check_pay_calldata(capture)
    print(f"proof calldata: {len(calldata)} bytes")

    simulated = rpc_call(
        "eth_call",
        [{"to": state["gate"], "data": "0x" + calldata.hex()}, "latest"],
    )
    print(f"gate eth_call answers {simulated} (the proven slot value)")

    nonce = int(rpc_call("eth_getTransactionCount", [state["address"], "latest"]), 16)
    frames = encode_frames(state["shim"], calldata)

    hash_payload = frame_tx_payload(state, nonce, frames, rlp_encode_quantity(65))
    sig_hash = keccak256(bytes([FRAME_TX_TYPE]) + hash_payload)
    key = PrivateKey(bytes.fromhex(state["key"].removeprefix("0x")))
    recoverable = key.sign_recoverable(sig_hash, hasher=None)
    signature = bytes([recoverable[64]]) + recoverable[:64]

    payload = frame_tx_payload(state, nonce, frames, rlp_encode_bytes(signature))
    raw = "0x" + (bytes([FRAME_TX_TYPE]) + payload).hex()
    (state_dir / "frame_tx.hex").write_text(raw + "\n")
    print(f"raw frame transaction written to {state_dir / 'frame_tx.hex'}")

    tx_hash = rpc_call("eth_sendRawTransaction", [raw])
    state["frameTx"] = tx_hash
    save_state(state_dir, state)
    print(f"submitted: {tx_hash}")
    print(f"explorer: {EXPLORER}")


def status(state_dir):
    state = load_state(state_dir)
    if "frameTx" not in state:
        raise SystemExit("error: no frame transaction recorded; run send first")
    receipt = rpc_call("eth_getTransactionReceipt", [state["frameTx"]])
    if receipt is None:
        print(f"{state['frameTx']} is not yet included")
        return
    print(json.dumps(receipt, indent=1))


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    state_dir = pathlib.Path(argv[2])
    if argv[1] == "key" and len(argv) == 3:
        make_key(state_dir)
    elif argv[1] == "deploy" and len(argv) == 4:
        deploy(state_dir, pathlib.Path(argv[3]))
    elif argv[1] == "send" and len(argv) == 4:
        send(state_dir, argv[3])
    elif argv[1] == "status" and len(argv) == 3:
        status(state_dir)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
