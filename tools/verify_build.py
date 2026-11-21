"""Prove the live mainnet contract is the pinned Fe compiler's output.

usage, with FE pointing at the pinned fe binary:

    FE=<fe-binary> python3 tools/verify_build.py

The check rebuilds BeaconProver's runtime bytecode from this repository's
source, fetches the code at the deployed address from mainnet, and fails
unless the chain's bytes are exactly the rebuilt runtime followed by the
two constructor arguments Fe appends (the EIP-4788 address and the open
end slot). Anyone can run it, and the provenance workflow runs it in
public, so "the EVM runs Fe's output" is a command, not a claim.

RPC_URL overrides the default public endpoint.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROVER = "0xDd356690270534B0DCe6755d77bCA554c9c54603"
BEACON_ROOTS = "000f3df6d732807ef1319fb7b8bb8522d0beac02"
OPEN_END = "ffffffffffffffff"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"


def main(argv):
    fe = os.environ.get("FE")
    if not fe:
        raise SystemExit("error: set FE to the pinned fe binary")
    version = subprocess.run([fe, "--version"], capture_output=True, text=True, check=True)
    print(f"compiler: {version.stdout.strip()}")

    with tempfile.TemporaryDirectory() as scratch:
        subprocess.run(
            [fe, "build", "-O", "2", "--emit", "runtime-bytecode", "--out-dir", scratch, "."],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        text = (pathlib.Path(scratch) / "BeaconProver.runtime.bin").read_text().strip()
    built = bytes.fromhex(text.removeprefix("0x"))
    print(f"rebuilt runtime: {len(built)} bytes")

    expected_tail = bytes.fromhex(BEACON_ROOTS.rjust(64, "0") + OPEN_END.ljust(64, "0"))

    rpc = os.environ.get("RPC_URL", DEFAULT_RPC)
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [PROVER, "latest"]}
    ).encode()
    request = urllib.request.Request(
        rpc, data=body, headers={"Content-Type": "application/json", "User-Agent": "assay-provenance"}
    )
    answer = json.load(urllib.request.urlopen(request, timeout=30))
    chain = bytes.fromhex(answer["result"][2:])
    print(f"code at {PROVER}: {len(chain)} bytes")

    if chain != built + expected_tail:
        if not chain.startswith(built):
            raise SystemExit("error: the chain's code is not the rebuilt runtime")
        raise SystemExit(
            f"error: the appended constructor arguments differ: {chain[len(built):].hex()}"
        )
    print("the mainnet contract is byte for byte this source compiled by the pinned Fe,")
    print("followed by its two constructor arguments (the 4788 address and the open end slot)")


if __name__ == "__main__":
    main(sys.argv)
