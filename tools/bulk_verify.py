"""Verify thousands of real mainnet accounts and slots from one beacon root.

usage: bulk_verify.py <assay-cli-binary> [--accounts N] [--blocks K] [--out PATH]

Anchors at the chain head exactly like capture_beacon.py chain: block N is
head minus 2, its child names the beacon block whose root the EIP-4788
contract exposes, and the three payload proofs bind the execution state root
to that one trusted 32-byte input. The account set is harvested from the
transactions of the K blocks ending at N, senders and recipients in order of
first appearance, so the sample is real, diverse and reproducible from the
block range alone. Every account fixture is oracle-checked at capture, then
verified in batches by the committed native CLI; contracts additionally
prove storage slots 0 and 1, present or absent. The receipts file is written
only when every batch exits 0, so a partial or failed run records nothing.

The default endpoints are the public nodes, overridable with RPC_URL and
BEACON_URL. Nothing in the repository is modified except the receipts file
named by --out (default docs/bulk_receipts.json).
"""

import argparse
import concurrent.futures
import datetime
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import capture_beacon
import capture_getproof
import oracle_mpt

ROOT = pathlib.Path(__file__).resolve().parent.parent
EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
BATCH_SIZE = 200
THROTTLE_SECONDS = 0.12


def fail(message):
    raise SystemExit(f"FAIL {message}")


def with_retries(call, what, attempts=4):
    for attempt in range(1, attempts + 1):
        try:
            return call()
        except SystemExit as error:
            if attempt == attempts:
                raise
            transient = "proof window" in str(error) or "not available" in str(error)
            if attempt == 1 or not transient:
                print(f"retry {attempt} after: {what}: {error}")
            time.sleep(0.8 if transient else 2 * attempt)


def harvest_accounts(url, end_number, block_count, wanted):
    seen = {}
    for number in range(end_number - block_count + 1, end_number + 1):
        block = with_retries(
            lambda tag=hex(number): capture_getproof.rpc(url, "eth_getBlockByNumber", [tag, True]),
            f"block {number}",
        )
        if block is None:
            fail(f"block {number} not found")
        for transaction in block.get("transactions", []):
            for key in ("from", "to"):
                address = transaction.get(key)
                if isinstance(address, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
                    seen.setdefault(address.lower(), None)
        time.sleep(THROTTLE_SECONDS)
    addresses = list(seen)
    if len(addresses) < wanted:
        fail(f"only {len(addresses)} distinct accounts in {block_count} blocks, wanted {wanted}")
    return addresses[:wanted]


def capture_anchor(url):
    head = int(with_retries(lambda: capture_getproof.rpc(url, "eth_blockNumber", []), "head"), 16)
    number = head - 2
    header = capture_getproof.block_header(url, hex(number))
    child = capture_getproof.block_header(url, hex(number + 1))
    if child["parentHash"] != header["hash"]:
        fail("block N+1 does not extend block N; the head moved, run again")
    beacon_root = child["parentBeaconBlockRoot"]
    response = capture_beacon.beacon_get(f"/eth/v2/beacon/blocks/{beacon_root}")
    capture_beacon.check_version(response)
    block = capture_beacon.t.BeaconBlock.from_obj(response["data"]["message"])
    if capture_beacon.hex32(block.hash_tree_root()) != beacon_root:
        fail("computed beacon block root differs from parentBeaconBlockRoot")
    payload = block.body.execution_payload
    if int(payload.block_number) != number:
        fail(f"payload block number {int(payload.block_number)}, expected {number}")
    if capture_beacon.hex32(payload.state_root) != header["stateRoot"]:
        fail("payload state_root differs from execution block N")
    if capture_beacon.hex32(payload.block_hash) != header["hash"]:
        fail("payload block_hash differs from execution block N")
    fields = {f"execution_payload.{f}": f for f in ("state_root", "block_number", "block_hash")}
    positions = {name: capture_beacon.oracle_ssz.payload_gindex(f) for name, f in fields.items()}
    capture_beacon.check_positions(
        capture_beacon.t.BeaconBlock,
        {name: ["body", "execution_payload", f] for name, f in fields.items()},
        positions,
    )
    proofs = []
    for name, gindex in positions.items():
        leaf, siblings = capture_beacon.branch(block.get_backing(), gindex)
        proofs.append(capture_beacon.proof_json(name, gindex, leaf, siblings))
    beacon_header = capture_beacon.t.BeaconBlockHeader(
        slot=block.slot,
        proposer_index=block.proposer_index,
        parent_root=block.parent_root,
        state_root=block.state_root,
        body_root=block.body.hash_tree_root(),
    )
    return {
        "beaconRoot": beacon_root,
        "header": header,
        "child": child,
        "headerJson": capture_beacon.header_json(beacon_header),
        "proofs": proofs,
        "slot": int(block.slot),
        "number": number,
    }


def capture_account(url, name, address, header):
    fixture = with_retries(
        lambda: capture_getproof.build_fixture(url, name, address, header, []),
        f"account {address}",
        attempts=12,
    )
    code_hash = fixture["proof"]["codeHash"].lower()
    analysis = oracle_mpt.analyze(fixture)
    receipt = {"address": address, "contract": False, "present": analysis["present"], "slots": []}
    if analysis["present"] and code_hash != EMPTY_CODE_HASH:
        receipt["contract"] = True
        slots = [capture_getproof.slot_word("0"), capture_getproof.slot_word("1")]
        fixture = with_retries(
            lambda: capture_getproof.build_fixture(url, name, address, header, slots),
            f"storage {address}",
            attempts=12,
        )
        for entry in oracle_mpt.analyze(fixture)["slots"]:
            key = entry["key"]
            slot_hex = "0x" + key.hex() if isinstance(key, (bytes, bytearray)) else key
            receipt["slots"].append({"slot": slot_hex, "present": entry["present"]})
    return fixture, receipt


def verify_batches(binary, work, anchor, names):
    verified_accounts = 0
    verified_slots = 0
    batches = [names[i:i + BATCH_SIZE] for i in range(0, len(names), BATCH_SIZE)]
    for position, batch in enumerate(batches):
        chain = {
            "name": f"chain_bulk_{position:03d}",
            "kind": "beacon_chain",
            "consensusVersion": capture_beacon.oracle_ssz.CONSENSUS_VERSION,
            "beacon": {"blockRoot": anchor["beaconRoot"], "header": anchor["headerJson"]},
            "execution": {
                "header": anchor["header"],
                "childHeader": anchor["child"],
                "mptFixtures": batch,
            },
            "proofs": anchor["proofs"],
        }
        path = work / f"chain_bulk_{position:03d}.json"
        path.write_text(json.dumps(chain))
        done = subprocess.run(
            [binary, "verify", str(path)],
            capture_output=True,
            text=True,
            timeout=900,
        )
        if done.returncode != 0:
            fail(
                f"the CLI refused batch {position} (exit {done.returncode}):\n"
                f"{done.stdout[-2000:]}{done.stderr[-2000:]}"
            )
        verdict = re.search(r"verified: (\d+) linked accounts and (\d+) slots", done.stdout)
        if not verdict:
            fail(f"batch {position} output holds no verdict line")
        verified_accounts += int(verdict.group(1))
        verified_slots += int(verdict.group(2))
        print(f"batch {position + 1}/{len(batches)}: {verdict.group(1)} accounts, {verdict.group(2)} slots")
    return verified_accounts, verified_slots


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--accounts", type=int, default=2000)
    parser.add_argument("--blocks", type=int, default=12)
    parser.add_argument("--out", default=str(ROOT / "docs" / "bulk_receipts.json"))
    arguments = parser.parse_args(argv[1:])
    binary = str(pathlib.Path(arguments.binary).resolve())
    url = capture_beacon.env("RPC_URL")
    capture_beacon.check_network()
    head = int(with_retries(lambda: capture_getproof.rpc(url, "eth_blockNumber", []), "head"), 16)
    harvest_end = head - 2
    addresses = harvest_accounts(url, harvest_end, arguments.blocks, arguments.accounts)
    print(f"harvested {len(addresses)} distinct accounts from {arguments.blocks} blocks ending at {harvest_end}")
    anchor = capture_anchor(url)
    print(f"anchored: beacon slot {anchor['slot']}, execution block {anchor['number']}, root {anchor['beaconRoot']}")
    with tempfile.TemporaryDirectory() as scratch:
        work = pathlib.Path(scratch)
        names = [f"acct_{index:05d}" for index in range(len(addresses))]
        receipts = [None] * len(addresses)
        done_count = 0
        def capture_one(index):
            fixture, receipt = capture_account(url, names[index], addresses[index], anchor["header"])
            (work / f"{names[index]}.json").write_text(json.dumps(fixture))
            return index, receipt
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            for index, receipt in pool.map(capture_one, range(len(addresses))):
                receipts[index] = receipt
                done_count += 1
                if done_count % 200 == 0:
                    print(f"captured {done_count}/{len(addresses)}")
        accounts, slots = verify_batches(binary, work, anchor, names)
    if accounts != len(receipts):
        fail(f"CLI verified {accounts} accounts but {len(receipts)} were captured")
    expected_slots = sum(len(r["slots"]) for r in receipts)
    if slots != expected_slots:
        fail(f"CLI verified {slots} slots but {expected_slots} were captured")
    when = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    payload = {
        "meta": {
            "when": when,
            "beaconSlot": anchor["slot"],
            "beaconRoot": anchor["beaconRoot"],
            "executionBlock": anchor["number"],
            "blockRange": [harvest_end - arguments.blocks + 1, harvest_end],
            "accounts": accounts,
            "slots": slots,
            "contracts": sum(1 for r in receipts if r["contract"]),
            "reproduce": f"python3 -I tools/bulk_verify.py <cli> --accounts {arguments.accounts} --blocks {arguments.blocks}",
        },
        "receipts": receipts,
    }
    out = pathlib.Path(arguments.out)
    out.write_text(json.dumps(payload) + "\n")
    print(f"verified: {accounts} accounts and {slots} slots from one beacon root; receipts at {out}")


if __name__ == "__main__":
    main(sys.argv)
