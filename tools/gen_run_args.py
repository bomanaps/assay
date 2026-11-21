"""Build docs/run.json, the live arguments behind the site's Run buttons.

usage:

    python3 -I tools/gen_run_args.py <fixtures-dir> <out-json> [check]

Each entry is one ready eth_call to the mainnet BeaconProver: the selector,
the fully encoded calldata, what the return words mean, and the 4788
timestamp key the proof anchors at. A visitor's browser sends the call and
Ethereum itself re-verifies the proof at that moment. The timestamp key is
in the output because the 4788 ring buffer holds roughly 27 hours of
roots; the page computes freshness from it and refuses to show a dead
button.

The tool builds entries for whichever fixture files exist in the
directory, so the six-hour pipeline feeds it chain captures and the daily
pipeline adds the state-heavy kinds. With `check` it sends every call to
the RPC in RPC_URL (publicnode by default) and fails unless the live
contract answers, so no argument set reaches the site unverified.
"""

import json
import os
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from oracle_mpt import keccak256, to_int, hex_bytes

PROVER = "0xDd356690270534B0DCe6755d77bCA554c9c54603"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"


def word(value):
    if isinstance(value, bytes):
        return value.rjust(32, b"\x00")
    return value.to_bytes(32, "big")


def encode(values):
    heads, tails = [], []
    static_size = 0
    for kind, value in values:
        static_size += 32
    blob = b""
    for kind, value in values:
        if kind == "word":
            heads.append(word(value))
        elif kind == "bytes":
            heads.append(None)
            padded = value + b"\x00" * (-len(value) % 32)
            tails.append(word(len(value)) + padded)
        elif kind == "words":
            heads.append(None)
            tails.append(word(len(value)) + b"".join(word(v) for v in value))
        elif kind == "tuple":
            heads.append(None)
            tails.append(encode(value))
        elif kind == "bytesarray":
            heads.append(None)
            inner_heads, inner_tail = [], b""
            for item in value:
                inner_heads.append(word(32 * len(value) + len(inner_tail)))
                padded = item + b"\x00" * (-len(item) % 32)
                inner_tail += word(len(item)) + padded
            tails.append(word(len(value)) + b"".join(inner_heads) + inner_tail)
        else:
            raise SystemExit(f"error: unknown kind {kind}")
    out, tail_at = b"", static_size
    tail_index = 0
    for head in heads:
        if head is None:
            tail = tails[tail_index]
            tail_index += 1
            out += word(tail_at)
            tail_at += len(tail)
        else:
            out += head
    return out + b"".join(tails)


def header_words(header):
    return [
        ("word", int(header["slot"])),
        ("word", int(header["proposer_index"])),
        ("word", hex_bytes(header["parent_root"], 32)),
        ("word", hex_bytes(header["state_root"], 32)),
        ("word", hex_bytes(header["body_root"], 32)),
    ]


def proof_named(fixture, name):
    return next(p for p in fixture["proofs"] if p["field"] == name)


def timestamp_key(fixture):
    return to_int(fixture["execution"]["childHeader"]["timestamp"])


def calldata(signature, values):
    return keccak256(signature.encode())[:4] + encode(values)


def nodes_of(items):
    return [hex_bytes(n) for n in items]


def entry_storage(chain, storage):
    state = proof_named(chain, "execution_payload.state_root")
    slot_entry = storage["proof"]["storageProof"][0]
    data = calldata(
        "proveStorage(uint64,(uint64,uint64,bytes32,bytes32,bytes32),bytes32,bytes32[],address,bytes[],uint256,bytes[])",
        [("word", timestamp_key(chain))]
        + header_words(chain["beacon"]["header"])
        + [
            ("word", hex_bytes(state["leaf"], 32)),
            ("words", [hex_bytes(b, 32) for b in state["branch"]]),
            ("word", hex_bytes(storage["proof"]["address"], 20)),
            ("bytesarray", nodes_of(storage["proof"]["accountProof"])),
            ("word", int(slot_entry["key"], 16)),
            ("bytesarray", nodes_of(slot_entry["proof"])),
        ],
    )
    return {
        "id": "storage",
        "title": "Prove a storage slot",
        "story": "USDC's slot 0 proven from the beacon root: SSZ branch to the execution state root, then the account and storage tries.",
        "returns": [
            {"label": "slot value", "type": "uint256"},
            {"label": "beacon slot", "type": "uint64"},
        ],
        "account": storage["proof"]["address"],
        "calldata": "0x" + data.hex(),
    }


def entry_payload(chain):
    multi = chain["payloadMultiproof"]
    state = proof_named(chain, "execution_payload.state_root")
    receipts = proof_named(chain, "execution_payload.receipts_root")
    number = proof_named(chain, "execution_payload.block_number")
    block_hash = proof_named(chain, "execution_payload.block_hash")
    data = calldata(
        "provePayload(uint64,(uint64,uint64,bytes32,bytes32,bytes32),bytes32,bytes32,uint64,bytes32,bytes32[])",
        [("word", timestamp_key(chain))]
        + header_words(chain["beacon"]["header"])
        + [
            ("word", hex_bytes(state["leaf"], 32)),
            ("word", hex_bytes(receipts["leaf"], 32)),
            ("word", int.from_bytes(hex_bytes(number["leaf"], 32)[:8], "little")),
            ("word", hex_bytes(block_hash["leaf"], 32)),
            ("words", [hex_bytes(h, 32) for h in multi["helpers"]]),
        ],
    )
    return {
        "id": "payload",
        "title": "Prove the whole payload",
        "story": "State root, receipts root, block number and block hash in one 14-helper multiproof, 17 hashes instead of 48.",
        "returns": [
            {"label": "block number", "type": "uint64"},
            {"label": "beacon slot", "type": "uint64"},
        ],
        "calldata": "0x" + data.hex(),
    }


def entry_receipt(chain, receipt):
    anchored = proof_named(chain, "execution_payload.receipts_root")
    data = calldata(
        "proveReceipt(uint64,(uint64,uint64,bytes32,bytes32,bytes32),bytes32,bytes32[],uint64,bytes[])",
        [("word", timestamp_key(chain))]
        + header_words(chain["beacon"]["header"])
        + [
            ("word", hex_bytes(anchored["leaf"], 32)),
            ("words", [hex_bytes(b, 32) for b in anchored["branch"]]),
            ("word", int(receipt["txIndex"], 16)),
            ("bytesarray", nodes_of(receipt["proof"])),
        ],
    )
    return {
        "id": "receipt",
        "title": "Prove a transaction outcome",
        "story": "A receipt from the block's receipt trie: status, gas used, type and log count, anchored through the beacon root.",
        "returns": [
            {"label": "succeeded", "type": "bool"},
            {"label": "cumulative gas", "type": "uint64"},
            {"label": "tx type", "type": "uint64"},
            {"label": "log count", "type": "uint64"},
            {"label": "beacon slot", "type": "uint64"},
        ],
        "calldata": "0x" + data.hex(),
    }


def entry_log(chain, receipt):
    anchored = proof_named(chain, "execution_payload.receipts_root")
    data = calldata(
        "proveLog(uint64,(uint64,uint64,bytes32,bytes32,bytes32),bytes32,bytes32[],uint64,uint64,bytes[])",
        [("word", timestamp_key(chain))]
        + header_words(chain["beacon"]["header"])
        + [
            ("word", hex_bytes(anchored["leaf"], 32)),
            ("words", [hex_bytes(b, 32) for b in anchored["branch"]]),
            ("word", int(receipt["txIndex"], 16)),
            ("word", int(receipt["log"]["index"], 16)),
            ("bytesarray", nodes_of(receipt["proof"])),
        ],
    )
    return {
        "id": "log",
        "title": "Prove an event log",
        "story": "One emitted event, address and topics and data hash, proven out of the receipt trie.",
        "returns": [
            {"label": "emitter", "type": "address"},
            {"label": "topic count", "type": "uint64"},
            {"label": "topic 0", "type": "bytes32"},
            {"label": "topic 1", "type": "bytes32"},
            {"label": "topic 2", "type": "bytes32"},
            {"label": "topic 3", "type": "bytes32"},
            {"label": "data hash", "type": "bytes32"},
            {"label": "data length", "type": "uint64"},
            {"label": "beacon slot", "type": "uint64"},
        ],
        "calldata": "0x" + data.hex(),
    }


def entry_validator(fixture):
    record = fixture["validator"]
    index = int(fixture["validatorIndex"])
    whole = proof_named(fixture, f"validators[{index}]")
    data = calldata(
        "proveValidator(uint64,(uint64,uint64,bytes32,bytes32,bytes32),uint64,(bytes,bytes32,uint64,bool,uint64,uint64,uint64,uint64),bytes32[])",
        [("word", timestamp_key(fixture))]
        + header_words(fixture["beacon"]["header"])
        + [
            ("word", index),
            (
                "tuple",
                [
                    ("bytes", hex_bytes(record["pubkey"])),
                    ("word", hex_bytes(record["withdrawal_credentials"], 32)),
                    ("word", int(record["effective_balance"])),
                    ("word", 1 if record["slashed"] else 0),
                    ("word", int(record["activation_eligibility_epoch"])),
                    ("word", int(record["activation_epoch"])),
                    ("word", int(record["exit_epoch"])),
                    ("word", int(record["withdrawable_epoch"])),
                ],
            ),
            ("words", [hex_bytes(b, 32) for b in whole["branch"]]),
        ],
    )
    return {
        "id": "validator",
        "title": "Prove a validator record",
        "story": "A whole validator record, all eight fields, proven from the registry fifty hash levels deep.",
        "returns": [
            {"label": "beacon slot", "type": "uint64"},
        ],
        "calldata": "0x" + data.hex(),
    }


def entry_history(fixture):
    position = f"block_roots[{int(fixture['targetSlot']) % 8192}]"
    element = proof_named(fixture, position)
    data = calldata(
        "proveHistoricalRoot(uint64,(uint64,uint64,bytes32,bytes32,bytes32),uint64,bytes32,bytes32[])",
        [("word", timestamp_key(fixture))]
        + header_words(fixture["beacon"]["header"])
        + [
            ("word", int(fixture["targetSlot"])),
            ("word", hex_bytes(fixture["historicalRoot"], 32)),
            ("words", [hex_bytes(b, 32) for b in element["branch"]]),
        ],
    )
    return {
        "id": "history",
        "title": "Prove yesterday's block root",
        "story": "An older block root from the state's 8,192-slot window, one more branch from the same anchor.",
        "returns": [
            {"label": "proven slot", "type": "uint64"},
            {"label": "anchor slot", "type": "uint64"},
        ],
        "calldata": "0x" + data.hex(),
    }


def entry_deephistory(fixture):
    summary = proof_named(
        fixture, f"historical_summaries[{fixture['summaryIndex']}].block_summary_root"
    )
    element = proof_named(
        fixture, f"block_summary[{int(fixture['targetSlot']) % 8192}]"
    )
    data = calldata(
        "proveDeepHistoricalRoot(uint64,(uint64,uint64,bytes32,bytes32,bytes32),uint64,bytes32,bytes32,bytes32[],bytes32[])",
        [("word", timestamp_key(fixture))]
        + header_words(fixture["beacon"]["header"])
        + [
            ("word", int(fixture["targetSlot"])),
            ("word", hex_bytes(fixture["historicalRoot"], 32)),
            ("word", hex_bytes(fixture["summaryRoot"], 32)),
            ("words", [hex_bytes(b, 32) for b in summary["branch"]]),
            ("words", [hex_bytes(b, 32) for b in element["branch"]]),
        ],
    )
    return {
        "id": "deephistory",
        "title": "Prove a 2023 block root",
        "story": "A block root from the first Capella period, 3.6 years back, through the frozen historical summaries.",
        "returns": [
            {"label": "proven slot", "type": "uint64"},
            {"label": "anchor slot", "type": "uint64"},
        ],
        "calldata": "0x" + data.hex(),
    }


def eth_call(rpc, data):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": PROVER, "data": data}, "latest"],
        }
    )
    request = urllib.request.Request(
        rpc,
        data=body.encode(),
        headers={"Content-Type": "application/json", "User-Agent": "assay-run"},
    )
    with urllib.request.urlopen(request, timeout=30) as reply:
        answer = json.load(reply)
    if "error" in answer:
        raise SystemExit(f"error: the live contract refused: {answer['error']}")
    return answer["result"]


def main(argv):
    if len(argv) not in (3, 4) or (len(argv) == 4 and argv[3] != "check"):
        raise SystemExit(__doc__)
    fixtures = pathlib.Path(argv[1])
    out = pathlib.Path(argv[2])

    def load(name):
        path = fixtures / f"{name}.json"
        return json.loads(path.read_text()) if path.exists() else None

    chain = load("chain_beacon")
    entries = []
    if chain:
        storage = load("chain_storage_usdc")
        receipt = load("chain_receipt_logged")
        key = timestamp_key(chain)
        slot = int(chain["beacon"]["header"]["slot"])
        fresh = [entry_payload(chain)]
        if storage:
            fresh.insert(0, entry_storage(chain, storage))
        if receipt:
            fresh.append(entry_receipt(chain, receipt))
            fresh.append(entry_log(chain, receipt))
        for item in fresh:
            item["timestampKey"] = key
            item["beaconSlot"] = slot
        entries += fresh
    validator = load("validator_beacon")
    if validator:
        item = entry_validator(validator)
        item["timestampKey"] = timestamp_key(validator)
        item["beaconSlot"] = int(validator["beacon"]["header"]["slot"])
        entries.append(item)
    history = load("history_day_old")
    if history:
        item = entry_history(history)
        item["timestampKey"] = timestamp_key(history)
        item["beaconSlot"] = int(history["beacon"]["header"]["slot"])
        entries.append(item)
    deep = load("history_capella_first")
    if deep:
        item = entry_deephistory(deep)
        item["timestampKey"] = timestamp_key(deep)
        item["beaconSlot"] = int(deep["beacon"]["header"]["slot"])
        entries.append(item)

    if not entries:
        raise SystemExit("error: no fixtures found to build entries from")

    if len(argv) == 4:
        rpc = os.environ.get("RPC_URL", DEFAULT_RPC)
        for item in entries:
            answer = eth_call(rpc, item["calldata"])
            if len(answer) < 2 + 64:
                raise SystemExit(f"error: {item['id']} answered {answer}")
            print(f"checked {item['id']}: the live contract answered {len(answer)//2 - 1} bytes")

    existing = {}
    if out.exists():
        existing = {e["id"]: e for e in json.loads(out.read_text())["entries"]}
    fresh_ids = {item["id"] for item in entries}
    if len(argv) == 4:
        import time

        window = 8191 * 12 - 1800
        for name, kept in list(existing.items()):
            if name in fresh_ids:
                continue
            if time.time() - kept["timestampKey"] > window:
                continue
            try:
                answer = eth_call(rpc, kept["calldata"])
                if len(answer) < 2 + 64:
                    raise ValueError(answer)
                print(f"rechecked kept {name}: still answering")
            except SystemExit as refusal:
                print(f"dropping kept {name}: {refusal}")
                del existing[name]
    for item in entries:
        existing[item["id"]] = item
    order = ["storage", "payload", "receipt", "log", "validator", "history", "deephistory"]
    merged = [existing[name] for name in order if name in existing]
    out.write_text(
        json.dumps({"contract": PROVER, "entries": merged}, indent=1) + "\n"
    )
    print(f"wrote {out}: {len(merged)} entries, {len(entries)} refreshed")


if __name__ == "__main__":
    main(sys.argv)
