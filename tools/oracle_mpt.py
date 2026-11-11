"""Independent Merkle-Patricia proof verifier for eth_getProof fixtures.

usage: oracle_mpt.py <fixture.json> [...]

For every fixture the block header is RLP encoded and hashed and must equal the
recorded block hash, so the state root is bound to the block. The account
proof is then walked from that state root to the account leaf and the decoded
account is compared with the fields the RPC returned. Every storage proof is
walked from the account's storage root to the slot's value and compared with
the RPC value. A key that the trie does not contain is reported as absent,
which must agree with an RPC value of zero or an RPC account with the four
default fields. Clients report an absent account's storageHash and codeHash
either as the empty trie root and empty code hash (geth) or as zero (seen from
publicnode and Alchemy in November 2026); both are accepted, and only when the
walk itself proves the account absent. The exit status is nonzero on any disagreement.

A synthetic trie fixture (kind synthetic_trie, from synth_trie.py) lists each
trie's root, its hashed nodes, and cases of a key, the value it claims or null
for an absent key, and the indices of the nodes in the key's proof. Every case
is walked from the root and must reach exactly the claimed value, keys may not
repeat within a trie, and every listed node must be used by some proof.

A child reference shorter than 32 bytes is the child node embedded in its
parent. The walk descends into such a child directly; eth_getProof does not
list embedded nodes separately.

The RLP codec and trie walk are written here from scratch so that this file
shares no code with the Fe implementation. Keccak-256 comes from pycryptodome.
"""

import json
import pathlib
import sys

from Crypto.Hash import keccak

EMPTY_STORAGE_ROOT = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
EMPTY_CODE_HASH = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
ABSENT_ACCOUNT_ZEROS = (0, 0, bytes(32), bytes(32))

HEADER_FIELDS = [
    ("parentHash", "hash"),
    ("sha3Uncles", "hash"),
    ("miner", "address"),
    ("stateRoot", "hash"),
    ("transactionsRoot", "hash"),
    ("receiptsRoot", "hash"),
    ("logsBloom", "bytes"),
    ("difficulty", "quantity"),
    ("number", "quantity"),
    ("gasLimit", "quantity"),
    ("gasUsed", "quantity"),
    ("timestamp", "quantity"),
    ("extraData", "bytes"),
    ("mixHash", "hash"),
    ("nonce", "bytes"),
    ("baseFeePerGas", "quantity"),
    ("withdrawalsRoot", "hash"),
    ("blobGasUsed", "quantity"),
    ("excessBlobGas", "quantity"),
    ("parentBeaconBlockRoot", "hash"),
    ("requestsHash", "hash"),
]


class ProofError(Exception):
    pass


def keccak256(data):
    return keccak.new(digest_bits=256, data=data).digest()


def rlp_encode_bytes(data):
    if len(data) == 1 and data[0] < 0x80:
        return data
    return rlp_length(len(data), 0x80) + data


def rlp_encode_list(items):
    payload = b"".join(items)
    return rlp_length(len(payload), 0xC0) + payload


def rlp_length(length, offset):
    if length < 56:
        return bytes([offset + length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(encoded)]) + encoded


def rlp_encode_quantity(value):
    if value == 0:
        return rlp_encode_bytes(b"")
    return rlp_encode_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def rlp_split(data):
    if not data:
        raise ProofError("empty rlp input")
    prefix = data[0]
    if prefix < 0x80:
        return False, data[0:1], data[1:]
    if prefix < 0xB8:
        length = prefix - 0x80
        payload, rest = data[1 : 1 + length], data[1 + length :]
        if len(payload) != length:
            raise ProofError("short string")
        if length == 1 and payload[0] < 0x80:
            raise ProofError("non canonical single byte")
        return False, payload, rest
    if prefix < 0xC0:
        is_list, length_length = False, prefix - 0xB7
    elif prefix < 0xF8:
        length = prefix - 0xC0
        payload, rest = data[1 : 1 + length], data[1 + length :]
        if len(payload) != length:
            raise ProofError("short list")
        return True, payload, rest
    else:
        is_list, length_length = True, prefix - 0xF7
    if len(data) < 1 + length_length:
        raise ProofError("truncated length prefix")
    length = int.from_bytes(data[1 : 1 + length_length], "big")
    if data[1] == 0 or length < 56:
        raise ProofError("non canonical length")
    start = 1 + length_length
    payload, rest = data[start : start + length], data[start + length :]
    if len(payload) != length:
        raise ProofError("short item")
    return is_list, payload, rest


def rlp_decode_payload(is_list, payload):
    if not is_list:
        return payload
    items = []
    while payload:
        inner_is_list, inner_payload, payload = rlp_split(payload)
        items.append(rlp_decode_payload(inner_is_list, inner_payload))
    return items


def rlp_decode(data):
    is_list, payload, rest = rlp_split(data)
    if rest:
        raise ProofError("trailing bytes after rlp item")
    return rlp_decode_payload(is_list, payload)


def nibbles_of(data):
    out = []
    for byte in data:
        out.append(byte >> 4)
        out.append(byte & 0x0F)
    return out


def decode_hex_prefix(encoded):
    if not encoded:
        raise ProofError("empty hex prefix path")
    nibbles = nibbles_of(encoded)
    flag = nibbles[0]
    if flag > 3:
        raise ProofError(f"bad hex prefix flag {flag}")
    is_leaf = flag >= 2
    if flag & 1:
        return is_leaf, nibbles[1:]
    if nibbles[1] != 0:
        raise ProofError("even length path with nonzero padding nibble")
    return is_leaf, nibbles[2:]


def walk(root, key, nodes):
    path = nibbles_of(key)
    expected = root
    position = 0
    depth = 0
    items = None
    while True:
        if items is None:
            if depth >= len(nodes):
                raise ProofError("proof ended before a terminal node")
            node = nodes[depth]
            depth += 1
            if keccak256(node) != expected:
                raise ProofError(f"node {depth - 1} hashes to a value the parent does not reference")
            items = rlp_decode(node)
        if not isinstance(items, list):
            raise ProofError(f"node {depth - 1} is not a list")
        remaining = depth < len(nodes)
        if len(items) == 17:
            if position == len(path):
                if remaining:
                    raise ProofError("nodes after the branch that ends the key")
                return items[16] if items[16] else None
            child = items[path[position]]
            position += 1
        elif len(items) == 2:
            is_leaf, segment = decode_hex_prefix(items[0])
            if not is_leaf and not segment:
                raise ProofError("extension with an empty path")
            if path[position : position + len(segment)] != segment:
                if remaining:
                    raise ProofError("nodes after a path mismatch")
                return None
            position += len(segment)
            if is_leaf:
                if position != len(path):
                    raise ProofError("leaf reached before the key was consumed")
                if remaining:
                    raise ProofError("nodes after the leaf")
                return items[1]
            child = items[1]
        else:
            raise ProofError(f"node {depth - 1} has {len(items)} items")
        if isinstance(child, list):
            items = child
            continue
        if child == b"":
            if remaining:
                raise ProofError("nodes after an empty branch slot")
            return None
        if len(child) != 32:
            raise ProofError(f"child reference of length {len(child)}")
        expected = child
        items = None


def to_int(hex_text):
    if not isinstance(hex_text, str) or not hex_text.startswith("0x") or len(hex_text) < 3:
        raise ProofError(f"{hex_text!r} is not a 0x-prefixed quantity")
    digits = hex_text[2:]
    if not set(digits) <= HEX_DIGITS or (len(digits) > 1 and digits[0] == "0"):
        raise ProofError(f"{hex_text} is not a canonical quantity")
    return int(digits, 16)


HEX_DIGITS = set("0123456789abcdef")


def hex_bytes(text, length=None):
    if not isinstance(text, str) or not text.startswith("0x"):
        raise ProofError(f"{text!r} is not 0x-prefixed hex")
    digits = text[2:]
    if not set(digits) <= HEX_DIGITS:
        raise ProofError(f"{text} is not lowercase hex")
    if len(digits) % 2:
        raise ProofError(f"odd length hex {text}")
    if length is not None and len(digits) != 2 * length:
        raise ProofError(f"{text} is not exactly {length} bytes")
    return bytes.fromhex(digits)


def rlp_int(data):
    if not isinstance(data, bytes):
        raise ProofError("integer field is a list")
    if data and data[0] == 0:
        raise ProofError("integer with leading zero")
    return int.from_bytes(data, "big")


def has_inline_child(nodes):
    for node in nodes:
        for item in rlp_decode(node):
            if isinstance(item, list):
                return True
    return False


def encode_header(header):
    fields = []
    for name, kind in HEADER_FIELDS:
        if name not in header:
            break
        value = header[name]
        if kind == "quantity":
            fields.append(rlp_encode_quantity(to_int(value)))
        elif kind == "hash":
            fields.append(rlp_encode_bytes(hex_bytes(value, 32)))
        elif kind == "address":
            fields.append(rlp_encode_bytes(hex_bytes(value, 20)))
        else:
            fields.append(rlp_encode_bytes(hex_bytes(value)))
    return rlp_encode_list(fields)


def check_header(header):
    encoded = encode_header(header)
    actual = keccak256(encoded)
    expected = hex_bytes(header["hash"], 32)
    if actual != expected:
        raise ProofError(f"header hashes to {actual.hex()}, recorded hash is {expected.hex()}")
    return encoded


MPT_KINDS = ("account", "storage")


def analyze(fixture):
    kind = fixture.get("kind")
    if kind not in MPT_KINDS:
        raise ProofError(f"not a trie fixture: kind {kind!r}")
    header = fixture["header"]
    proof = fixture["proof"]
    if (kind == "storage") != bool(proof["storageProof"]):
        raise ProofError(f"kind {kind} does not match {len(proof['storageProof'])} storage proofs")
    chain_id = fixture["chainId"]
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
        raise ProofError(f"chain id {chain_id!r} is not a positive integer")
    header_rlp = check_header(header)
    state_root = hex_bytes(header["stateRoot"], 32)
    address = hex_bytes(proof["address"], 20)
    nodes = [hex_bytes(n) for n in proof["accountProof"]]

    leaf = walk(state_root, keccak256(address), nodes)
    if leaf is None:
        present = False
        nonce, balance, storage_root, code_hash = 0, 0, EMPTY_STORAGE_ROOT, EMPTY_CODE_HASH
    else:
        present = True
        if not isinstance(leaf, bytes):
            raise ProofError("account leaf value is a list")
        fields = rlp_decode(leaf)
        if not isinstance(fields, list) or len(fields) != 4:
            raise ProofError("account leaf is not a 4 item list")
        nonce, balance = rlp_int(fields[0]), rlp_int(fields[1])
        storage_root, code_hash = fields[2], fields[3]
        if not isinstance(storage_root, bytes) or not isinstance(code_hash, bytes):
            raise ProofError("account roots are lists")
        if len(storage_root) != 32 or len(code_hash) != 32:
            raise ProofError("account roots are not 32 bytes")

    expected = (
        to_int(proof["nonce"]),
        to_int(proof["balance"]),
        hex_bytes(proof["storageHash"], 32),
        hex_bytes(proof["codeHash"], 32),
    )
    decoded = (nonce, balance, storage_root, code_hash)
    if decoded != expected and not (not present and expected == ABSENT_ACCOUNT_ZEROS):
        raise ProofError("decoded account disagrees with the rpc account fields")

    slots = []
    for entry in proof["storageProof"]:
        slot = hex_bytes(entry["key"], 32)
        if any(s["key"] == slot for s in slots):
            raise ProofError(f"slot {entry['key']} is proven twice")
        slot_nodes = [hex_bytes(n) for n in entry["proof"]]
        if storage_root == EMPTY_STORAGE_ROOT:
            if slot_nodes:
                raise ProofError("storage proof nodes for an empty storage trie")
            found = None
        else:
            found = walk(storage_root, keccak256(slot), slot_nodes)
        if found is None:
            value = 0
        else:
            if not isinstance(found, bytes):
                raise ProofError("storage leaf value is a list")
            value = rlp_int(rlp_decode(found))
            if value == 0:
                raise ProofError("storage leaf holding zero")
        if value != to_int(entry["value"]):
            raise ProofError(f"slot {entry['key']} decodes to {value}, rpc says {entry['value']}")
        slots.append(
            {
                "key": slot,
                "path": keccak256(slot),
                "present": found is not None,
                "value": value,
                "nodes": slot_nodes,
                "inline": has_inline_child(slot_nodes),
            }
        )

    return {
        "chain_id": chain_id,
        "block_number": to_int(header["number"]),
        "block_hash": hex_bytes(header["hash"], 32),
        "header_rlp": header_rlp,
        "state_root": state_root,
        "address": address,
        "path": keccak256(address),
        "nodes": nodes,
        "inline": has_inline_child(nodes),
        "present": present,
        "nonce": nonce,
        "balance": balance,
        "storage_root": storage_root,
        "code_hash": code_hash,
        "slots": slots,
    }


SYNTHETIC_KIND = "synthetic_trie"


def analyze_synthetic(fixture):
    if fixture.get("kind") != SYNTHETIC_KIND:
        raise ProofError(f"not a synthetic trie fixture: kind {fixture.get('kind')!r}")
    tries = []
    for t, entry in enumerate(fixture["tries"]):
        root = hex_bytes(entry["root"], 32)
        nodes = [hex_bytes(n) for n in entry["nodes"]]
        if len(set(nodes)) != len(nodes):
            raise ProofError(f"trie {t} lists a node twice")
        used = set()
        keys = set()
        cases = []
        for c, case in enumerate(entry["cases"]):
            key = hex_bytes(case["key"], 32)
            if key in keys:
                raise ProofError(f"trie {t} case {c} repeats a key")
            keys.add(key)
            proof = case["proof"]
            if not proof or any(not isinstance(i, int) or isinstance(i, bool) or not 0 <= i < len(nodes) for i in proof):
                raise ProofError(f"trie {t} case {c} has a bad proof index list")
            used.update(proof)
            found = walk(root, key, [nodes[i] for i in proof])
            claimed = None if case["value"] is None else hex_bytes(case["value"])
            if claimed == b"":
                raise ProofError(f"trie {t} case {c} claims an empty value")
            if found != claimed:
                raise ProofError(f"trie {t} case {c} walks to a value the fixture does not claim")
            cases.append({"key": key, "value": found, "proof": proof})
        if used != set(range(len(nodes))):
            raise ProofError(f"trie {t} lists nodes no proof uses")
        tries.append({"root": root, "nodes": nodes, "cases": cases})
    return tries


def check_fixture(fixture):
    result = analyze(fixture)
    report = [f"header hash verified, {len(result['header_rlp'])} rlp bytes"]
    if result["present"]:
        report.append(f"account present nonce={result['nonce']} balance={result['balance']}")
    else:
        report.append("account absent")
    for slot in result["slots"]:
        kind = "present" if slot["present"] else "absent"
        inline = " inline-child" if slot["inline"] else ""
        report.append(f"slot {slot['key'].hex()[-8:]} {kind} value={slot['value']}{inline}")
    if result["inline"]:
        report.append("account proof has inline child")
    return report


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    failures = 0
    for text in argv[1:]:
        path = pathlib.Path(text)
        try:
            fixture = json.loads(path.read_text())
            if fixture.get("kind") == SYNTHETIC_KIND:
                tries = analyze_synthetic(fixture)
                present = sum(1 for t in tries for c in t["cases"] if c["value"] is not None)
                absent = sum(1 for t in tries for c in t["cases"] if c["value"] is None)
                print(f"ok   {path.name}: {len(tries)} tries, {present} present and {absent} absent keys walked")
                continue
            if fixture.get("kind") not in MPT_KINDS:
                print(f"skip {path.name}: kind {fixture.get('kind')}")
                continue
            for line in check_fixture(fixture):
                print(f"ok   {path.name}: {line}")
        except (ProofError, KeyError, TypeError, ValueError) as e:
            print(f"FAIL {path.name}: {type(e).__name__}: {e}")
            failures += 1
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv)
