"""Capture eth_getProof responses as fixtures, and verify captured fixtures.

usage: capture_getproof.py capture <name> <address> <block> [slot ...]
       capture_getproof.py verify <fixture.json> [...]

capture reads the JSON-RPC endpoint from the RPC_URL environment variable.
<name> is lowercase letters, digits and underscores.
<block> is a decimal block number, "finalized", or "latest".
Slots are hex, with or without 0x, and are padded to 32 bytes.
The block header is fetched first and the proof is then requested by that
block's hash, so header and proof always describe the same block. Before a
fixture is written, the first account node is hashed and compared with the
header's state root. capture writes fixtures/<name>.json and replaces or adds
that name's row in fixtures/README.md.

verify re-runs the state root check on existing fixtures and exits nonzero on
any mismatch.

Requires Python 3.10+ and pycryptodome for Keccak-256.
"""

import datetime
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

from Crypto.Hash import keccak

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
README = FIXTURES / "README.md"
README_HEADER = (
    "# Fixtures\n\n"
    "Raw eth_getProof captures with the block header they were proven against. "
    "Each row's command reproduces its file bit for bit given the same chain history. "
    "Run `python3 tools/capture_getproof.py verify fixtures/*.json` to recheck every state root.\n\n"
    "| name | kind | chain id | block | block hash | state root | captured (UTC) | command |\n"
    "|---|---|---|---|---|---|---|---|\n"
)
NAME_PATTERN = re.compile(r"^[a-z0-9_]+$")
HEX_PATTERN = re.compile(r"^(0x)?[0-9a-fA-F]+$")


def fail(message):
    raise SystemExit(f"error: {message}")


def keccak256(data):
    return "0x" + keccak.new(digest_bits=256, data=data).hexdigest()


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
    if "error" in reply:
        fail(f"{method}: {reply['error']}")
    if "result" not in reply:
        fail(f"{method}: reply has no result")
    return reply["result"]


def slot_word(text):
    if not HEX_PATTERN.match(text):
        fail(f"slot is not hex: {text}")
    digits = text[2:] if text.startswith("0x") else text
    if len(digits) > 64:
        fail(f"slot longer than 32 bytes: {text}")
    return "0x" + digits.lower().rjust(64, "0")


def parse_block(text):
    if text in ("finalized", "latest"):
        return text
    if not text.isdigit():
        fail(f"block must be a decimal number, finalized, or latest: {text}")
    return hex(int(text))


def check_state_root(fixture):
    nodes = fixture["proof"]["accountProof"]
    if not nodes:
        return "account proof has no nodes"
    actual = keccak256(bytes.fromhex(nodes[0][2:]))
    expected = fixture["header"]["stateRoot"].lower()
    if actual != expected:
        return f"root node hashes to {actual}, header state root is {expected}"
    return None


def readme_rows():
    if not README.exists():
        return []
    rows = []
    for line in README.read_text().splitlines():
        if line.startswith("| ") and not line.startswith("| name "):
            rows.append(line)
    return rows


def write_readme(rows):
    rows = sorted(rows, key=lambda r: r.split("|")[1].strip())
    README.write_text(README_HEADER + "".join(row + "\n" for row in rows))


def capture(argv):
    if len(argv) < 3:
        fail(__doc__)
    name, address, block_arg = argv[0], argv[1].lower(), argv[2]
    if not NAME_PATTERN.match(name):
        fail(f"bad fixture name: {name}")
    if not (len(address) == 42 and HEX_PATTERN.match(address) and address.startswith("0x")):
        fail(f"bad address: {address}")
    slots = []
    for raw in argv[3:]:
        word = slot_word(raw)
        if word not in slots:
            slots.append(word)
    url = os.environ.get("RPC_URL")
    if not url:
        fail("RPC_URL is not set")

    header = rpc(url, "eth_getBlockByNumber", [parse_block(block_arg), False])
    if header is None:
        fail(f"block not found: {block_arg}")
    header.pop("transactions", None)
    header.pop("withdrawals", None)
    header.pop("uncles", None)
    block_number = int(header["number"], 16)
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    proof = rpc(url, "eth_getProof", [address, slots, {"blockHash": header["hash"]}])

    fixture = {
        "name": name,
        "kind": "storage" if slots else "account",
        "chainId": chain_id,
        "header": header,
        "proof": proof,
    }
    problem = check_state_root(fixture)
    if problem:
        fail(f"refusing to write {name}: {problem}")

    FIXTURES.mkdir(exist_ok=True)
    path = FIXTURES / f"{name}.json"
    path.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")

    captured = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    command = "capture_getproof.py capture " + " ".join([name, address, str(block_number), *slots])
    row = (
        f"| {name} | {fixture['kind']} | {chain_id} | {block_number} | {header['hash']} | "
        f"{header['stateRoot']} | {captured} | `{command}` |"
    )
    rows = [r for r in readme_rows() if r.split("|")[1].strip() != name]
    write_readme(rows + [row])

    print(path)
    print(f"block {block_number} state root {header['stateRoot']} verified against account node 0")
    print(f"accountProof nodes: {len(proof['accountProof'])}")
    for entry in proof["storageProof"]:
        print(f"storage {entry['key']}: value {entry['value']}, {len(entry['proof'])} nodes")


def verify(paths):
    if not paths:
        fail(__doc__)
    failures = 0
    for text in paths:
        path = pathlib.Path(text)
        fixture = json.loads(path.read_text())
        problem = check_state_root(fixture)
        if problem:
            print(f"FAIL {path}: {problem}")
            failures += 1
        else:
            print(f"ok   {path}")
    if failures:
        raise SystemExit(1)


def main(argv):
    if len(argv) < 2:
        fail(__doc__)
    if argv[1] == "capture":
        capture(argv[2:])
    elif argv[1] == "verify":
        verify(argv[2:])
    else:
        fail(__doc__)


if __name__ == "__main__":
    main(sys.argv)
