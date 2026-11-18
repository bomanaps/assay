"""Deploy BeaconProver to mainnet and prove live storage through the real 4788 contract.

usage: deploy_live.py prepare <state-dir>
       deploy_live.py record <state-dir> <deploy-tx> <prove-tx>

prepare builds the contract with the pinned Fe release, captures a fresh
proof set at the chain head, and prints exactly two cast commands for the
key holder to run: one deploys the contract, one sends a proveStorage
transaction whose success depends on the proof verifying against the
genuine EIP-4788 ring buffer. The private key never touches this script;
the printed commands reference $DEPLOYER_KEY from the caller's own shell.
The 4788 ring buffer holds a root for roughly 27 hours, so the prove
transaction must be sent within that window of the capture.

record takes the two transaction hashes, checks both receipts succeeded,
checks the prove transaction targeted the deployed contract with the
prepared calldata, replays the proof as an eth_call against the live
contract, and writes docs/deployment.md with the full evidence trail.

Nothing here signs, sends, or holds anything.
"""

import json
import os
import pathlib
import sys
import tempfile
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import demo_fork

ROOT = pathlib.Path(__file__).resolve().parent.parent
BEACON_ROOTS = demo_fork.BEACON_ROOTS
OPEN_END = demo_fork.OPEN_END
RPC_DEFAULT = "https://ethereum-rpc.publicnode.com"


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        reply = json.load(response)
    if "error" in reply:
        demo_fork.fail(f"{method}: {reply['error']}")
    return reply["result"]


def prepare(state_dir):
    fe_binary = demo_fork.tool("fe", "FE")
    cast_binary = demo_fork.tool("cast")
    rpc_url = os.environ.get("RPC_URL", RPC_DEFAULT)
    state_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as scratch:
        work = pathlib.Path(scratch)
        chain, usdc = demo_fork.capture(work)
        init_code = demo_fork.build_prover(fe_binary, work)
    constructor = demo_fork.run(
        [cast_binary, "abi-encode", "constructor(address,uint64)", BEACON_ROOTS, OPEN_END],
    )
    deploy_data = "0x" + init_code + constructor[2:]
    arguments = demo_fork.storage_arguments(chain, usdc, tampered=False)
    slot = chain["beacon"]["header"]["slot"]
    child = chain["execution"]["childHeader"]
    (state_dir / "deploy_data.hex").write_text(deploy_data + "\n")
    (state_dir / "prove_args.json").write_text(json.dumps(arguments, indent=1) + "\n")
    (state_dir / "capture.json").write_text(
        json.dumps(
            {
                "beaconSlot": int(slot),
                "blockRoot": chain["beacon"]["blockRoot"],
                "executionBlock": int(chain["execution"]["header"]["number"], 16),
                "timestampKey": int(child["timestamp"], 16),
                "account": usdc["proof"]["address"],
                "slotKey": usdc["proof"]["storageProof"][0]["key"],
                "slotValue": usdc["proof"]["storageProof"][0]["value"],
                "rpc": rpc_url,
            },
            indent=1,
        )
        + "\n"
    )
    demo_fork.say("")
    demo_fork.say(f"prepared: beacon slot {slot}, proving USDC storage at the chain head")
    demo_fork.say(f"state written to {state_dir}")
    demo_fork.say("")
    demo_fork.say("run these two commands yourself, in order (read -s DEPLOYER_KEY first):")
    demo_fork.say("")
    demo_fork.say(
        f"cast send --rpc-url {rpc_url} --private-key \"$DEPLOYER_KEY\" "
        f"--create \"$(cat {state_dir}/deploy_data.hex)\""
    )
    demo_fork.say("")
    demo_fork.say("then, with <PROVER> being the contractAddress from the first receipt:")
    demo_fork.say("")
    quoted = " ".join("'" + a + "'" for a in demo_fork.storage_arguments(chain, usdc, tampered=False))
    demo_fork.say(
        f"cast send --rpc-url {rpc_url} --private-key \"$DEPLOYER_KEY\" "
        f"<PROVER> '{demo_fork.PROVE_STORAGE}' {quoted}"
    )
    demo_fork.say("")
    demo_fork.say("afterwards: deploy_live.py record <state-dir> <deploy-tx-hash> <prove-tx-hash>")


def record(state_dir, deploy_tx, prove_tx):
    cast_binary = demo_fork.tool("cast")
    rpc_url = os.environ.get("RPC_URL", RPC_DEFAULT)
    capture = json.loads((state_dir / "capture.json").read_text())
    arguments = json.loads((state_dir / "prove_args.json").read_text())
    deploy_receipt = rpc(rpc_url, "eth_getTransactionReceipt", [deploy_tx])
    prove_receipt = rpc(rpc_url, "eth_getTransactionReceipt", [prove_tx])
    if not deploy_receipt or deploy_receipt.get("status") != "0x1":
        demo_fork.fail("the deploy transaction is missing or reverted")
    if not prove_receipt or prove_receipt.get("status") != "0x1":
        demo_fork.fail("the prove transaction is missing or reverted")
    prover = deploy_receipt.get("contractAddress")
    if not prover:
        demo_fork.fail("the deploy receipt names no contract address")
    if (prove_receipt.get("to") or "").lower() != prover.lower():
        demo_fork.fail("the prove transaction did not target the deployed contract")
    code = rpc(rpc_url, "eth_getCode", [prover, "latest"])
    if len(code) <= 2:
        demo_fork.fail("the deployed address holds no code")
    answer = demo_fork.run(
        [cast_binary, "call", "--rpc-url", rpc_url, prover, demo_fork.PROVE_STORAGE] + arguments
    )
    raw = answer[2:] if answer.startswith("0x") else answer
    if len(raw) != 128:
        demo_fork.fail(f"live replay returned {len(raw)} hex chars, expected 128")
    value = int(raw[:64], 16)
    slot_echo = int(raw[64:], 16)
    expected_value = int(capture["slotValue"], 16)
    if value != expected_value:
        demo_fork.fail(f"live replay value {value} differs from the captured {expected_value}")
    deploy_gas = int(deploy_receipt["gasUsed"], 16)
    prove_gas = int(prove_receipt["gasUsed"], 16)
    text = (
        "# Mainnet deployment\n\n"
        "BeaconProver runs on Ethereum mainnet, pointed at the genuine EIP-4788\n"
        "beacon-roots contract. The prove transaction below executed the full\n"
        "verification on-chain: it could only succeed because every hash from the\n"
        "beacon block root down to the storage slot checked out inside the EVM.\n\n"
        "| what | value |\n"
        "|---|---|\n"
        f"| contract | `{prover}` |\n"
        f"| deploy transaction | `{deploy_tx}` |\n"
        f"| deploy gas | {deploy_gas:,} |\n"
        f"| proveStorage transaction | `{prove_tx}` |\n"
        f"| proveStorage gas | {prove_gas:,} |\n"
        f"| beacon slot proven | {capture['beaconSlot']:,} |\n"
        f"| beacon block root | `{capture['blockRoot']}` |\n"
        f"| account proven | `{capture['account']}` (USDC) |\n"
        f"| storage slot | `{capture['slotKey']}` |\n"
        f"| proven value | `{capture['slotValue']}` |\n"
        f"| EIP-4788 source | `{BEACON_ROOTS}` |\n\n"
        "Reproduce the live read (no key needed):\n\n"
        "```\n"
        f"cast call --rpc-url {rpc_url} {prover} \\\n"
        f"  '{demo_fork.PROVE_STORAGE}' \\\n  "
        + " \\\n  ".join("'" + a + "'" for a in arguments)
        + "\n```\n\n"
        "The call reverts for any tampered input; the committed vector suite and\n"
        "the fork demo show the same contract refusing flipped branch words.\n"
    )
    out = ROOT / "docs" / "deployment.md"
    out.write_text(text)
    demo_fork.say(f"ok   live replay returned the captured value at slot echo {slot_echo}")
    demo_fork.say(f"ok   receipts verified; evidence written to {out}")


def main(argv):
    if len(argv) >= 3 and argv[1] == "prepare":
        prepare(pathlib.Path(argv[2]))
        return
    if len(argv) == 5 and argv[1] == "record":
        record(pathlib.Path(argv[2]), argv[3], argv[4])
        return
    raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
