"""Capture eth_getProof responses as fixtures.

usage: capture_getproof.py capture <name> <address> <block> [slot ...]

capture reads the JSON-RPC endpoint from the RPC_URL environment variable.
<name> is lowercase letters, digits and underscores.
<block> is a decimal block number, "finalized", or "latest".
Slots are hex, with or without 0x, and are padded to 32 bytes.
The block header is fetched first and the proof is then requested by that
block's hash, so header and proof always describe the same block. The fixture
is built in memory and run through oracle_mpt.py; only then is
fixtures/<name>.json written and that name's row in fixtures/README.md replaced
or added. Every write goes to a temporary file that is renamed into place.

Requires Python 3.10+ and pycryptodome for Keccak-256.
"""

import datetime
import json
import os
import pathlib
import re
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
README = FIXTURES / "README.md"
README_HEADER = (
    "# Fixtures\n\n"
    "Captured proofs and the headers they are proven against. Trie fixtures (kind `account` or "
    "`storage`) come from `eth_getProof`; their command reproduces the file given the same chain "
    "history. Beacon fixtures (kind `beacon_chain` or `beacon_validator`) come from "
    "`tools/capture_beacon.py`: the chain capture takes the head minus two blocks, and the validator "
    "capture needs the finalized state named in its row. `synthetic_tries` is not captured: "
    "`tools/synth_trie.py generate` builds it from a fixed seed, and `synth_trie.py check` proves the "
    "committed file is what that seed gives. `ethereum_tests/` holds five trie vector files copied "
    "unchanged from ethereum/tests commit c67e485ff8b5be9abc8ad15345ec21aa22e290d9 (`TrieTests/`, MIT, "
    "license alongside); `test_oracles.py` checks that `synth_trie.py` rebuilds every root in them, and "
    "`tools/spec_crosscheck.py` checks the synthetic roots and these vectors against the trie of "
    "ethereum/execution-specs at the commit in `tools/requirements-spec.txt`.\n\n"
    "Check every fixture with `python3 -I tools/oracle_mpt.py fixtures/*.json` and "
    "`python3 -I tools/oracle_ssz.py fixtures/*.json`; each tool checks the kinds it knows and skips "
    "the rest.\n\n"
    "| name | kind | chain id | block or slot | block hash or beacon block root | state root "
    "| captured (UTC) | command |\n"
    "|---|---|---|---|---|---|---|---|\n"
)
NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]*")
HEX_PATTERN = re.compile(r"(0x)?[0-9a-fA-F]+")
ADDRESS_PATTERN = re.compile(r"0x[0-9a-f]{40}")
DECIMAL_PATTERN = re.compile(r"[0-9]+")
MPT_KINDS = ("account", "storage")


def fail(message):
    raise SystemExit(f"error: {message}")


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    headers = {"content-type": "application/json", "user-agent": "assay-capture/0.1"}
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            reply = json.load(response)
    except urllib.error.HTTPError as e:
        fail(f"{method}: HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        fail(f"{method}: {e.reason}")
    except json.JSONDecodeError:
        fail(f"{method}: reply is not JSON")
    if not isinstance(reply, dict):
        fail(f"{method}: reply is not a JSON object")
    if "error" in reply:
        fail(f"{method}: {reply['error']}")
    if "result" not in reply:
        fail(f"{method}: reply has no result")
    return reply["result"]


def slot_word(text):
    if not HEX_PATTERN.fullmatch(text):
        fail(f"slot is not hex: {text}")
    digits = text[2:] if text.startswith("0x") else text
    if len(digits) > 64:
        fail(f"slot longer than 32 bytes: {text}")
    return "0x" + digits.lower().rjust(64, "0")


def parse_block(text):
    if text in ("finalized", "latest"):
        return text
    if not DECIMAL_PATTERN.fullmatch(text):
        fail(f"block must be a decimal number, finalized, or latest: {text}")
    return hex(int(text))


def block_header(url, tag):
    header = rpc(url, "eth_getBlockByNumber", [tag, False])
    if header is None:
        fail(f"block not found: {tag}")
    for key in ("transactions", "withdrawals", "uncles"):
        header.pop(key, None)
    return header


def build_fixture(url, name, address, header, slots):
    if not NAME_PATTERN.fullmatch(name):
        fail(f"bad fixture name: {name}")
    if not ADDRESS_PATTERN.fullmatch(address):
        fail(f"bad address: {address}")
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    proof = rpc(url, "eth_getProof", [address, slots, {"blockHash": header["hash"]}])
    fixture = {
        "name": name,
        "kind": "storage" if slots else "account",
        "chainId": chain_id,
        "header": header,
        "proof": proof,
    }
    try:
        oracle_mpt.analyze(fixture)
    except oracle_mpt.ProofError as e:
        fail(f"refusing to write {name}: oracle rejected it: {e}")
    return fixture


def readme_row(name, kind, chain_id, block_or_slot, anchor_hash, state_root, command):
    captured = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    return (
        f"| {name} | {kind} | {chain_id} | {block_or_slot} | {anchor_hash} | {state_root} "
        f"| {captured} | `{command}` |"
    )


def fixture_row(fixture, command):
    header = fixture["header"]
    return readme_row(
        fixture["name"],
        fixture["kind"],
        fixture["chainId"],
        int(header["number"], 16),
        header["hash"],
        header["stateRoot"],
        command,
    )


def readme_rows():
    if not README.exists():
        return []
    rows = []
    for line in README.read_text().splitlines():
        if line.startswith("| ") and not line.startswith("| name "):
            rows.append(line)
    return rows


def write_atomically(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w") as out:
            out.write(text)
        os.replace(temp, path)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise


def commit(fixtures, rows):
    names = {fixture["name"] for fixture in fixtures}
    kept = [r for r in readme_rows() if r.split("|")[1].strip() not in names]
    ordered = sorted(kept + rows, key=lambda r: r.split("|")[1].strip())
    for fixture in fixtures:
        path = FIXTURES / f"{fixture['name']}.json"
        write_atomically(path, json.dumps(fixture, indent=2, sort_keys=True) + "\n")
        print(path)
    write_atomically(README, README_HEADER + "".join(row + "\n" for row in ordered))


def capture(argv):
    if len(argv) < 3:
        fail(__doc__)
    name, address, block_arg = argv[0], argv[1].lower(), argv[2]
    slots = []
    for raw in argv[3:]:
        word = slot_word(raw)
        if word not in slots:
            slots.append(word)
    url = os.environ.get("RPC_URL")
    if not url:
        fail("RPC_URL is not set")
    header = block_header(url, parse_block(block_arg))
    fixture = build_fixture(url, name, address, header, slots)
    block_number = int(header["number"], 16)
    command = "capture_getproof.py capture " + " ".join([name, address, str(block_number), *slots])
    commit([fixture], [fixture_row(fixture, command)])
    print(f"block {block_number} state root {header['stateRoot']} verified by oracle_mpt")


def main(argv):
    if len(argv) >= 2 and argv[1] == "capture":
        capture(argv[2:])
    else:
        fail(__doc__)


if __name__ == "__main__":
    main(sys.argv)
