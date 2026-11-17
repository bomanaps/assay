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
]

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
        for name in ("chain_beacon", "validator_beacon", "validator_slashed"):
            code, output = run(binary, fixtures / f"{name}.json")
            expect(f"{name} verifies", 0, "verified:", code, output, failures)
        linked = json.loads((fixtures / "chain_beacon.json").read_text())
        for trie in linked["execution"]["mptFixtures"]:
            shutil.copy(fixtures / f"{trie}.json", scratch / f"{trie}.json")
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
