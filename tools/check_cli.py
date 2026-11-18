"""Run the native CLI over the committed fixtures and tampered copies.

usage: check_cli.py <assay-binary> <fixtures-dir>

Every committed beacon fixture must verify with exit 0. Every tampered copy
must fail with exit 1 and name the failing fact, and every malformed input
must exit 2 without verifying anything. The tampers are written to a scratch
directory; nothing under the fixtures directory is modified. The exit status
is nonzero on any disagreement.
"""

import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile


def flip(text):
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def run(binary, path):
    done = subprocess.run(
        [binary, "verify", str(path)], capture_output=True, text=True, timeout=300
    )
    return done.returncode, done.stdout + done.stderr


CHAIN_TAMPERS = [
    ("header slot", 1, "header fields do not hash", lambda f: f["beacon"]["header"].update(slot=str(int(f["beacon"]["header"]["slot"]) + 1))),
    ("anchor root", 1, "do not hash to the anchor", lambda f: f["beacon"].update(blockRoot=flip(f["beacon"]["blockRoot"]))),
    ("state root branch word", 1, "branch does not reach", lambda f: proof(f, "execution_payload.state_root")["branch"].__setitem__(3, flip(proof(f, "execution_payload.state_root")["branch"][3]))),
    ("state root gindex", 1, "Fulu puts it at", lambda f: proof(f, "execution_payload.state_root").update(gindex="6435")),
    ("block number leaf", 1, "does not match the execution header's claim", lambda f: proof(f, "execution_payload.block_number").update(leaf=flip(proof(f, "execution_payload.block_number")["leaf"]))),
    ("state root header claim", 1, "does not match the execution header's claim", lambda f: f["execution"]["header"].update(stateRoot=flip(f["execution"]["header"]["stateRoot"]))),
    ("missing proof entry", 2, "no well-formed proof named", lambda f: f["proofs"].remove(proof(f, "execution_payload.state_root"))),
    ("empty links", 2, "links no trie fixtures", lambda f: f["execution"].update(mptFixtures=[])),
    ("traversal link name", 2, "not a plain fixture name", lambda f: f["execution"].update(mptFixtures=["../chain_storage_usdc"])),
    ("short branch", 1, "branch does not reach", lambda f: proof(f, "execution_payload.block_hash")["branch"].pop()),
    ("uppercase root hex", 2, "not canonical hex", lambda f: f["beacon"].update(blockRoot="0x" + f["beacon"]["blockRoot"][2:].upper())),
    ("kind", 2, "unknown fixture kind", lambda f: f.update(kind="beacon_blob")),
    ("multiproof helper word", 1, "multiproof does not reconstruct", lambda f: f["payloadMultiproof"]["helpers"].__setitem__(5, flip(f["payloadMultiproof"]["helpers"][5]))),
    ("multiproof truncated", 2, "need exactly 14", lambda f: f["payloadMultiproof"]["helpers"].pop()),
    ("multiproof missing helpers", 2, "holds no helpers", lambda f: f["payloadMultiproof"].pop("helpers")),
    ("multiproof gindices", 1, "do not name the four payload fields", lambda f: f["payloadMultiproof"]["gindices"].__setitem__(0, "9999")),
    ("multiproof missing gindices", 2, "names no gindices", lambda f: f["payloadMultiproof"].pop("gindices")),
    ("receipts root branch word", 1, "branch does not reach", lambda f: proof(f, "execution_payload.receipts_root")["branch"].__setitem__(3, flip(proof(f, "execution_payload.receipts_root")["branch"][3]))),
    ("receipts root header claim", 1, "multiproof does not reconstruct", lambda f: f["execution"]["header"].update(receiptsRoot=flip(f["execution"]["header"]["receiptsRoot"]))),
    ("empty receipt links", 2, "links no receipt fixtures", lambda f: f["execution"].update(receiptFixtures=[])),
    ("receipt traversal name", 2, "not a plain fixture name", lambda f: f["execution"].update(receiptFixtures=["../chain_receipt_logged"])),
]

HISTORY_TAMPERS = [
    ("target past the anchor", 1, "is not before the anchor", lambda f: f.update(targetSlot=f["beacon"]["header"]["slot"])),
    ("renamed target slot", 2, "no well-formed proof named", lambda f: f.update(targetSlot=str(int(f["targetSlot"]) + 1))),
    ("claimed root", 1, "does not encode the file's claimed historical root", lambda f: f.update(historicalRoot=flip(f["historicalRoot"]))),
    ("roots branch word", 1, "historical root branch does not reach", lambda f: history_proof(f)["branch"].__setitem__(5, flip(history_proof(f)["branch"][5]))),
    ("genesis root branch", 1, "genesis_validators_root", lambda f: proof(f, "genesis_validators_root")["branch"].__setitem__(0, flip(proof(f, "genesis_validators_root")["branch"][0]))),
    ("execution hash claim", 1, "does not match the execution header's claim", lambda f: f["execution"]["header"].update(hash=flip(f["execution"]["header"]["hash"]))),
]


DEEPHISTORY_TAMPERS = [
    ("pre-capella target", 1, "is before Capella", lambda f: f.update(targetSlot="6209535")),
    ("anchor-period target", 1, "anchor's own period", lambda f: f.update(targetSlot=str(int(f["beacon"]["header"]["slot"]) - 100))),
    ("summary index", 1, "does not match period", lambda f: f.update(summaryIndex=str(int(f["summaryIndex"]) + 1))),
    ("summary root claim", 1, "does not encode the file's claimed summary root", lambda f: f.update(summaryRoot=flip(f["summaryRoot"]))),
    ("historical root claim", 1, "does not encode the file's claimed historical root", lambda f: f.update(historicalRoot=flip(f["historicalRoot"]))),
    ("summary branch word", 1, "two-hop historical proof does not reach", lambda f: deep_summary_proof(f)["branch"].__setitem__(4, flip(deep_summary_proof(f)["branch"][4]))),
    ("vector branch word", 1, "two-hop historical proof does not reach", lambda f: deep_vector_proof(f)["branch"].__setitem__(4, flip(deep_vector_proof(f)["branch"][4]))),
    ("missing vector proof", 2, "no well-formed proof named block_summary", lambda f: f["proofs"].remove(deep_vector_proof(f))),
]


def deep_summary_proof(fixture):
    index = int(fixture["summaryIndex"])
    return proof(fixture, f"historical_summaries[{index}].block_summary_root")


def deep_vector_proof(fixture):
    position = int(fixture["targetSlot"]) % 8192
    return proof(fixture, f"block_summary[{position}]")


def history_proof(fixture):
    position = int(fixture["targetSlot"]) % 8192
    return proof(fixture, f"block_roots[{position}]")


VALIDATOR_TAMPERS = [
    ("effective balance", 1, "does not equal the record's hash tree root", lambda f: f["validator"].update(effective_balance=str(int(f["validator"]["effective_balance"]) + 1))),
    ("slashed flag", 1, "does not equal the record's hash tree root", lambda f: f["validator"].update(slashed=not f["validator"]["slashed"])),
    ("exit epoch", 1, "does not equal the record's hash tree root", lambda f: f["validator"].update(exit_epoch="123")),
    ("pubkey", 1, "does not equal the record's hash tree root", lambda f: f["validator"].update(pubkey=flip(f["validator"]["pubkey"]))),
    ("record proof gindex", 1, "whole-record proof claims gindex", lambda f: record_proof(f).update(gindex="1")),
    ("missing field proof", 2, "no well-formed proof named", lambda f: f["proofs"].remove(proof(f, f"validators[{f['validatorIndex']}].pubkey"))),
    ("execution hash claim", 1, "does not match the execution header's claim", lambda f: f["execution"]["header"].update(hash=flip(f["execution"]["header"]["hash"]))),
    ("validator index", 2, "no well-formed whole-record proof", lambda f: f.update(validatorIndex=str(int(f["validatorIndex"]) + 1))),
    ("validator index with renamed proofs", 1, "whole-record proof claims gindex", lambda f: rename_index(f)),
    ("genesis root branch", 1, "genesis_validators_root", lambda f: proof(f, "genesis_validators_root")["branch"].__setitem__(0, flip(proof(f, "genesis_validators_root")["branch"][0]))),
    ("fork version leaf", 1, "fork.current_version", lambda f: proof(f, "fork.current_version").update(leaf="0x" + "07" + proof(f, "fork.current_version")["leaf"][4:])),
    ("block hash branch", 1, "latest payload block hash: branch does not reach", lambda f: proof(f, "latest_execution_payload_header.block_hash")["branch"].pop()),
    ("record branch word", 1, "record branch does not reach the anchor root", lambda f: record_proof(f)["branch"].__setitem__(10, flip(record_proof(f)["branch"][10]))),
]


def rename_index(fixture):
    old = fixture["validatorIndex"]
    new = str(int(old) + 1)
    fixture["validatorIndex"] = new
    for entry in fixture["proofs"]:
        entry["field"] = entry["field"].replace(f"[{old}]", f"[{new}]")


def proof(fixture, name):
    return next(p for p in fixture["proofs"] if p["field"] == name)


def record_proof(fixture):
    return next(p for p in fixture["proofs"] if p["field"].endswith("]"))


def expect(label, expected_code, needle, code, output, failures):
    if code != expected_code:
        print(f"MISMATCH {label}: exit {code}, expected {expected_code}\n{output}")
        failures.append(label)
    elif needle and needle not in output:
        print(f"MISMATCH {label}: expected message containing {needle!r}\n{output}")
        failures.append(label)
    else:
        print(f"ok   {label} (exit {code})")


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    binary = str(pathlib.Path(argv[1]).resolve())
    fixtures = pathlib.Path(argv[2]).resolve()
    failures = []
    with tempfile.TemporaryDirectory() as scratch_text:
        scratch = pathlib.Path(scratch_text)
        for name in ("chain_beacon", "validator_beacon", "validator_slashed", "history_day_old", "history_capella_first"):
            code, output = run(binary, fixtures / f"{name}.json")
            expect(f"{name} verifies", 0, "verified:", code, output, failures)
        linked = json.loads((fixtures / "chain_beacon.json").read_text())
        for trie in linked["execution"]["mptFixtures"]:
            shutil.copy(fixtures / f"{trie}.json", scratch / f"{trie}.json")
        for receipt_name in linked["execution"].get("receiptFixtures", []):
            shutil.copy(fixtures / f"{receipt_name}.json", scratch / f"{receipt_name}.json")
        original = json.loads((fixtures / "chain_beacon.json").read_text())
        for label, expected_code, needle, tamper in CHAIN_TAMPERS:
            tampered = copy.deepcopy(original)
            tamper(tampered)
            target = scratch / "chain_beacon.json"
            target.write_text(json.dumps(tampered))
            code, output = run(binary, target)
            expect(f"chain {label}", expected_code, needle, code, output, failures)
        slot_value = scratch / "chain_beacon.json"
        tampered = copy.deepcopy(original)
        slot_entry = json.loads((fixtures / "chain_storage_usdc.json").read_text())
        slot_entry["proof"]["storageProof"][0]["value"] = flip(slot_entry["proof"]["storageProof"][0]["value"])
        (scratch / "chain_storage_usdc.json").write_text(json.dumps(slot_entry))
        slot_value.write_text(json.dumps(tampered))
        code, output = run(binary, slot_value)
        expect("chain linked slot value", 1, "chain_storage_usdc", code, output, failures)
        shutil.copy(fixtures / "chain_storage_usdc.json", scratch / "chain_storage_usdc.json")
        missing = copy.deepcopy(original)
        missing["execution"]["mptFixtures"].append("chain_storage_gone")
        slot_value.write_text(json.dumps(missing))
        code, output = run(binary, slot_value)
        expect("chain missing linked file", 2, "cannot read", code, output, failures)
        slot_value.write_text(json.dumps(original))
        logged_path = scratch / "chain_receipt_logged.json"
        logged_original = json.loads((fixtures / "chain_receipt_logged.json").read_text())
        receipt_file_tampers = [
            ("receipt log count claim", 1, "disagrees with the file's claims", lambda f: f["receipt"].update(logCount=hex(int(f["receipt"]["logCount"], 16) + 1))),
            ("receipt topic claim", 1, "disagrees with the file", lambda f: f["log"]["topics"].__setitem__(0, flip(f["log"]["topics"][0]))),
            ("receipt proof node", 1, "receipt proof rejected", lambda f: f["proof"].__setitem__(len(f["proof"]) - 1, flip(f["proof"][len(f["proof"]) - 1]))),
            ("receipt claims removed", 1, "the file claims none", lambda f: (f.pop("receipt"), f.pop("log"))),
            ("receipt foreign root", 1, "captured at a different receipts root", lambda f: f["header"].update(receiptsRoot=flip(f["header"]["receiptsRoot"]))),
        ]
        for label, expected_code, needle, tamper in receipt_file_tampers:
            tampered_receipt = copy.deepcopy(logged_original)
            tamper(tampered_receipt)
            logged_path.write_text(json.dumps(tampered_receipt))
            code, output = run(binary, slot_value)
            expect(f"chain {label}", expected_code, needle, code, output, failures)
        shutil.copy(fixtures / "chain_receipt_logged.json", logged_path)
        missing_receipt = copy.deepcopy(original)
        missing_receipt["execution"]["receiptFixtures"].append("chain_receipt_gone")
        slot_value.write_text(json.dumps(missing_receipt))
        code, output = run(binary, slot_value)
        expect("chain missing receipt file", 2, "cannot read", code, output, failures)
        original_history = json.loads((fixtures / "history_day_old.json").read_text())
        history_path = scratch / "history_day_old.json"
        for label, expected_code, needle, tamper in HISTORY_TAMPERS:
            tampered = copy.deepcopy(original_history)
            tamper(tampered)
            history_path.write_text(json.dumps(tampered))
            code, output = run(binary, history_path)
            expect(f"history {label}", expected_code, needle, code, output, failures)
        original_deep = json.loads((fixtures / "history_capella_first.json").read_text())
        deep_path = scratch / "history_capella_first.json"
        for label, expected_code, needle, tamper in DEEPHISTORY_TAMPERS:
            tampered = copy.deepcopy(original_deep)
            tamper(tampered)
            deep_path.write_text(json.dumps(tampered))
            code, output = run(binary, deep_path)
            expect(f"deephistory {label}", expected_code, needle, code, output, failures)
        original_validator = json.loads((fixtures / "validator_beacon.json").read_text())
        for label, expected_code, needle, tamper in VALIDATOR_TAMPERS:
            tampered = copy.deepcopy(original_validator)
            tamper(tampered)
            target = scratch / "validator_beacon.json"
            target.write_text(json.dumps(tampered))
            code, output = run(binary, target)
            expect(f"validator {label}", expected_code, needle, code, output, failures)
        bare = scratch / "bare.json"
        bare.write_text(json.dumps(json.loads((fixtures / "chain_storage_usdc.json").read_text())))
        code, output = run(binary, bare)
        expect("bare trie fixture refused", 2, "no trusted root", code, output, failures)
        not_json = scratch / "broken.json"
        not_json.write_text("{not json")
        code, output = run(binary, not_json)
        expect("non-JSON refused", 2, "not JSON", code, output, failures)
        code, output = run(binary, scratch / "absent.json")
        expect("missing file refused", 2, "cannot read", code, output, failures)
        done = subprocess.run([binary], capture_output=True, text=True, timeout=60)
        expect("usage shown", 2, "usage:", done.returncode, done.stdout + done.stderr, failures)
    if failures:
        raise SystemExit(f"{len(failures)} CLI checks disagreed")
    print("every CLI check agreed")


if __name__ == "__main__":
    main(sys.argv)
