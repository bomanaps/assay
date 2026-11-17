"""Prove live mainnet storage on a fork, through the real EIP-4788 contract.

usage: demo_fork.py

Captures a fresh beacon chain fixture at the chain head, starts anvil forked
at the execution block whose timestamp keys the EIP-4788 ring buffer, deploys
the BeaconProver bytecode built by the pinned Fe release against the genuine
beacon-roots contract at 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02, and
calls proveStorage with the captured USDC proof. The contract staticcalls the
real ring buffer, verifies the SSZ branch and both trie proofs, and returns
the slot value and the proven slot. A tampered branch is then submitted and
must revert.

Anyone can rerun this: it needs the fe release binary (FE environment
variable, or `fe` on PATH), anvil and cast from Foundry, python3 with
tools/requirements-capture.txt installed, and the two public endpoints
(override with RPC_URL and BEACON_URL). Nothing in the repository is
modified; all captures go to a temporary directory. The exit status is
nonzero if any step disagrees.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
BEACON_ROOTS = "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02"
OPEN_END = str(2**64 - 1)
ANVIL_PORT = "8571"
ANVIL_URL = f"http://127.0.0.1:{ANVIL_PORT}"
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
PROVE_STORAGE = (
    "proveStorage(uint64,(uint64,uint64,bytes32,bytes32,bytes32),bytes32,bytes32[],"
    "address,bytes[],uint256,bytes[])"
)


def say(line):
    print(line, flush=True)


def fail(message):
    raise SystemExit(f"FAIL {message}")


def tool(name, env_name=None):
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    found = shutil.which(name)
    if not found:
        fail(f"{name} is not on PATH" + (f" and {env_name} is not set" if env_name else ""))
    return found


def run(arguments, **keywords):
    done = subprocess.run(arguments, capture_output=True, text=True, timeout=600, **keywords)
    if done.returncode != 0:
        fail(f"{arguments[0]} failed:\n{done.stdout}{done.stderr}")
    return done.stdout.strip()


def capture(work):
    say("== capturing a fresh proof set at the chain head")
    tools_copy = work / "tools"
    shutil.copytree(ROOT / "tools", tools_copy, ignore=shutil.ignore_patterns("__pycache__"))
    (work / "fixtures").mkdir()
    environment = dict(os.environ)
    environment.setdefault("RPC_URL", "https://ethereum-rpc.publicnode.com")
    environment.setdefault("BEACON_URL", "https://ethereum-beacon-api.publicnode.com")
    attempts = 0
    while True:
        attempts += 1
        done = subprocess.run(
            [sys.executable, "-I", str(tools_copy / "capture_beacon.py"), "chain"],
            capture_output=True,
            text=True,
            timeout=600,
            env=environment,
            cwd=work,
        )
        if done.returncode == 0:
            break
        if attempts >= 4:
            fail(f"capture failed after {attempts} attempts:\n{done.stdout}{done.stderr}")
        say(f"   capture attempt {attempts} failed (the head moved); retrying")
        time.sleep(3)
    chain = json.loads((work / "fixtures" / "chain_beacon.json").read_text())
    usdc = json.loads((work / "fixtures" / "chain_storage_usdc.json").read_text())
    return chain, usdc


def build_prover(fe_binary, out_dir):
    say("== building BeaconProver with the pinned Fe release")
    version = run([fe_binary, "--version"])
    say(f"   {version}")
    run([fe_binary, "build", "-O", "2", "--emit", "bytecode", "--out-dir", str(out_dir), "."], cwd=ROOT)
    return (out_dir / "BeaconProver.bin").read_text().strip()


def rpc(method, params):
    request = urllib.request.Request(
        ANVIL_URL,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def start_anvil(anvil_binary, fork_url, block_number, log_path):
    say(f"== forking mainnet at block {block_number} (the 4788 key block)")
    log = open(log_path, "w")
    process = subprocess.Popen(
        [
            anvil_binary,
            "--fork-url",
            fork_url,
            "--fork-block-number",
            str(block_number),
            "--port",
            ANVIL_PORT,
            "--silent",
        ],
        stdout=log,
        stderr=log,
    )
    deadline = time.time() + 120
    while time.time() < deadline:
        if process.poll() is not None:
            fail(f"anvil exited early; log at {log_path}")
        try:
            if "result" in rpc("eth_chainId", []):
                return process
        except OSError:
            pass
        time.sleep(1)
    process.kill()
    fail("anvil did not become ready")


def proof_named(chain, name):
    return next(p for p in chain["proofs"] if p["field"] == name)


def bracketed(items):
    return "[" + ",".join(items) + "]"


def header_tuple(header):
    return "({},{},{},{},{})".format(
        header["slot"],
        header["proposer_index"],
        header["parent_root"],
        header["state_root"],
        header["body_root"],
    )


def storage_arguments(chain, usdc, tampered):
    state_proof = proof_named(chain, "execution_payload.state_root")
    branch = list(state_proof["branch"])
    if tampered:
        word = branch[4]
        branch[4] = word[:-1] + ("0" if word[-1] != "0" else "1")
    entry = usdc["proof"]["storageProof"][0]
    return [
        str(chain["execution"]["childHeader"]["timestamp"]),
        header_tuple(chain["beacon"]["header"]),
        state_proof["leaf"],
        bracketed(branch),
        usdc["proof"]["address"],
        bracketed(usdc["proof"]["accountProof"]),
        str(int(entry["key"], 16)),
        bracketed(entry["proof"]),
    ]


def main():
    fe_binary = tool("fe", "FE")
    anvil_binary = tool("anvil")
    cast_binary = tool("cast")
    fork_url = os.environ.get("RPC_URL", "https://ethereum-rpc.publicnode.com")
    with tempfile.TemporaryDirectory() as scratch:
        work = pathlib.Path(scratch)
        chain, usdc = capture(work)
        child = chain["execution"]["childHeader"]
        child_number = int(child["number"], 16)
        child_timestamp = int(child["timestamp"], 16)
        block_root = chain["beacon"]["blockRoot"]
        slot = chain["beacon"]["header"]["slot"]
        say(f"   beacon slot {slot}, block root {block_root}")
        say(f"   4788 key: timestamp {child_timestamp} of execution block {child_number}")
        init_code = build_prover(fe_binary, work)
        anvil = start_anvil(anvil_binary, fork_url, child_number, work / "anvil.log")
        try:
            key = f"0x{child_timestamp:064x}"
            answer = run([cast_binary, "call", BEACON_ROOTS, key, "--rpc-url", ANVIL_URL])
            if answer != block_root:
                fail(f"the real 4788 contract answered {answer}, capture says {block_root}")
            say(f"ok   the genuine 4788 ring buffer holds our beacon root: {answer}")
            arguments = run(
                [cast_binary, "abi-encode", "constructor(address,uint64)", BEACON_ROOTS, OPEN_END],
            )
            deployed = run(
                [
                    cast_binary,
                    "send",
                    "--json",
                    "--rpc-url",
                    ANVIL_URL,
                    "--private-key",
                    ANVIL_KEY,
                    "--create",
                    "0x" + init_code + arguments[2:],
                ],
            )
            receipt = json.loads(deployed)
            if receipt.get("status") not in ("0x1", 1, "1"):
                fail(f"deployment reverted: {deployed}")
            prover = receipt["contractAddress"]
            say(f"ok   BeaconProver deployed at {prover}, pointed at the real {BEACON_ROOTS}")
            reply = run(
                [cast_binary, "call", prover, PROVE_STORAGE]
                + storage_arguments(chain, usdc, tampered=False)
                + ["--rpc-url", ANVIL_URL],
            )
            raw = reply[2:]
            if len(raw) != 128:
                fail(f"unexpected reply {reply}")
            value = int(raw[0:64], 16)
            proven_slot = int(raw[64:128], 16)
            claimed = int(usdc["proof"]["storageProof"][0]["value"], 16)
            if value != claimed or proven_slot != slot_number(chain):
                fail(f"proven ({value}, {proven_slot}) disagrees with capture ({claimed}, {slot_number(chain)})")
            say(f"ok   proveStorage returned USDC slot 0 = {value} at beacon slot {proven_slot}")
            tampered = subprocess.run(
                [cast_binary, "call", prover, PROVE_STORAGE]
                + storage_arguments(chain, usdc, tampered=True)
                + ["--rpc-url", ANVIL_URL],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if tampered.returncode == 0:
                fail("a tampered branch was accepted")
            say("ok   the same call with one branch word flipped reverts")
            say("")
            say("verified: live mainnet storage proven on-chain from the beacon root alone,")
            say("through the genuine EIP-4788 contract, on a fork anyone can recreate")
        finally:
            anvil.kill()


def slot_number(chain):
    return int(chain["beacon"]["header"]["slot"])


if __name__ == "__main__":
    main()
