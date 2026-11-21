"""Prove any mainnet account and storage slot, end to end, in one command.

usage: prove.py <assay-cli-binary> <address> [slot]

Captures a fresh proof set for the address at the chain head, verifies every
hash locally with the native CLI, the same code the on-chain contract runs,
and then prints a ready-made cast command that asks the live mainnet
BeaconProver to verify the same proof inside the EVM. The printed command is
a read-only cast call: it needs no key, costs nothing, and anyone can run it.

The slot defaults to 0. The target contract defaults to the deployed
mainnet BeaconProver and follows PROVER_ADDRESS. Capture endpoints follow
RPC_URL and BEACON_URL, defaulting to the public nodes; the printed command
always names a public endpoint (override with PRINT_RPC), never the capture
endpoint, so a private RPC key can never leak into shared output. Nothing in the repository
is modified; the capture goes to a temporary directory. The exit status is
nonzero if the capture or any proof fails, and nothing is printed as
provable then.
"""

import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import bulk_verify
import capture_beacon
import capture_getproof
import demo_fork

MAINNET_PROVER = "0xDd356690270534B0DCe6755d77bCA554c9c54603"
ADDRESS_PATTERN = re.compile(r"0x[0-9a-fA-F]{40}")
PROVE_STORAGE = demo_fork.PROVE_STORAGE


def fail(message):
    raise SystemExit(f"FAIL {message}")


def chain_file(anchor, fixture_name):
    return {
        "name": "prove_chain",
        "kind": "beacon_chain",
        "consensusVersion": capture_beacon.oracle_ssz.CONSENSUS_VERSION,
        "beacon": {"blockRoot": anchor["beaconRoot"], "header": anchor["headerJson"]},
        "execution": {
            "header": anchor["header"],
            "childHeader": anchor["child"],
            "mptFixtures": [fixture_name],
        },
        "proofs": anchor["proofs"],
    }


def cast_arguments(anchor, fixture, slot_word):
    state_proof = None
    for proof in anchor["proofs"]:
        if proof["field"] == "execution_payload.state_root":
            state_proof = proof
    if state_proof is None:
        fail("the capture holds no state root proof")
    entry = None
    for candidate in fixture["proof"]["storageProof"]:
        if candidate["key"] == slot_word or int(candidate["key"], 16) == int(slot_word, 16):
            entry = candidate
    if entry is None:
        fail("the capture holds no proof for the requested slot")
    return [
        str(int(anchor["child"]["timestamp"], 16)),
        demo_fork.header_tuple(anchor["headerJson"]),
        state_proof["leaf"],
        demo_fork.bracketed(state_proof["branch"]),
        fixture["proof"]["address"],
        demo_fork.bracketed(fixture["proof"]["accountProof"]),
        str(int(entry["key"], 16)),
        demo_fork.bracketed(entry["proof"]),
    ], entry


def main(argv):
    if len(argv) not in (3, 4):
        raise SystemExit(__doc__)
    binary = str(pathlib.Path(argv[1]).resolve())
    address = argv[2].lower()
    if not ADDRESS_PATTERN.fullmatch(address):
        fail(f"not an address: {argv[2]}")
    slot_text = argv[3] if len(argv) == 4 else "0"
    if slot_text.startswith("0x"):
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", slot_text):
            fail(f"not a storage slot: {slot_text}")
        slot_word = capture_getproof.slot_word(slot_text)
    else:
        if not re.fullmatch(r"[0-9]{1,78}", slot_text) or int(slot_text) >= 1 << 256:
            fail(f"not a storage slot: {slot_text}")
        slot_word = capture_getproof.slot_word(hex(int(slot_text)))
    url = capture_beacon.env("RPC_URL")
    capture_beacon.check_network()
    prover = os.environ.get("PROVER_ADDRESS", MAINNET_PROVER)
    anchor = bulk_verify.capture_anchor(url)
    print(f"anchored: beacon slot {anchor['slot']}, execution block {anchor['number']}")
    fixture = bulk_verify.with_retries(
        lambda: capture_getproof.build_fixture(url, "prove_target", address, anchor["header"], [slot_word]),
        f"proof for {address}",
        attempts=12,
    )
    with tempfile.TemporaryDirectory() as scratch:
        work = pathlib.Path(scratch)
        (work / "prove_target.json").write_text(json.dumps(fixture))
        (work / "prove_chain.json").write_text(json.dumps(chain_file(anchor, "prove_target")))
        done = subprocess.run(
            [binary, "verify", str(work / "prove_chain.json")],
            capture_output=True,
            text=True,
            timeout=600,
        )
        print(done.stdout, end="")
        if done.returncode != 0:
            fail(f"the local verifier refused the capture (exit {done.returncode}):\n{done.stderr}")
    arguments, entry = cast_arguments(anchor, fixture, slot_word)
    rpc = os.environ.get("PRINT_RPC", "https://ethereum-rpc.publicnode.com")
    quoted = " \\\n  ".join("'" + a + "'" for a in arguments)
    print()
    print(f"proven locally: {address} slot {slot_text} = {int(entry['value'], 16)}")
    print()
    print("ask Ethereum mainnet to verify the same proof, free, no key needed:")
    print()
    print(f"cast call --rpc-url {rpc} {prover} \\")
    print(f"  '{PROVE_STORAGE}' \\")
    print(f"  {quoted}")
    print()
    print("the call returns the proven value and the beacon slot; any tampered")
    print("byte makes the same call revert. The EIP-4788 contract holds this")
    print("anchor for about 27 hours; after that, run prove again for a fresh one.")


if __name__ == "__main__":
    main(sys.argv)
