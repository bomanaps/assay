"""Build seeded random Merkle-Patricia tries and proofs for every query.

usage: synth_trie.py generate
       synth_trie.py check

generate builds the trie set from a fixed seed and writes
fixtures/synthetic_tries.json. check rebuilds it in memory and exits nonzero
if the committed file differs, so CI proves the file is what the seed gives.

Each trie is built from its key to value map, top down: one key is a leaf, keys
that share a nonempty prefix sit under an extension, and otherwise a branch
splits them by their next nibble and holds the value of a key that ends there.
Keys of any length are accepted, so the builder can be checked against the
ethereum/tests trie vectors; the generated set uses 32-byte keys only. A node whose RLP encoding is shorter than 32
bytes is embedded in its parent; every other node, and always the root, is
referenced by its Keccak-256 hash. Proofs come from following a key through the
builder's own tree, never from decoding RLP, so this file shares no code and no
walk logic with oracle_mpt.py or the Fe verifier.

Keys are 32 bytes, as the verifier expects, and are drawn near keys already in
the trie so that extensions, deep branches and embedded nodes appear. Every
trie also gets absent keys that end at an empty branch slot, inside a leaf's
path, or inside an extension's path. The set must contain every structural
feature in FEATURES at least once, or generation fails.
"""

import json
import pathlib
import random
import sys

from Crypto.Hash import keccak

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "fixtures" / "synthetic_tries.json"
NAME = "synthetic_tries"
KIND = "synthetic_trie"
SEED = 4788
TRIE_COUNT = 50
MAX_KEYS = 12
ABSENT_PER_TRIE = 6
ABSENT_CANDIDATES = 64
KEY_NIBBLES = 64
HASH_LEN = 32

FEATURES = (
    "root_leaf",
    "hashed_branch",
    "embedded_branch",
    "hashed_extension",
    "embedded_extension",
    "hashed_leaf",
    "embedded_leaf",
    "extension_to_hashed_child",
    "extension_to_embedded_child",
    "odd_extension_path",
    "even_extension_path",
    "odd_leaf_path",
    "even_leaf_path",
    "long_list_node",
    "single_byte_value",
    "long_value",
    "absent_empty_slot",
    "absent_leaf_divergence",
    "absent_extension_divergence",
    "absent_inside_embedded",
)


def keccak256(data):
    return keccak.new(digest_bits=256, data=data).digest()


def encode_length(length, offset):
    if length < 56:
        return bytes([offset + length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(encoded)]) + encoded


def encode_string(data):
    if len(data) == 1 and data[0] < 0x80:
        return data
    return encode_length(len(data), 0x80) + data


def encode_list(encoded_items):
    payload = b"".join(encoded_items)
    return encode_length(len(payload), 0xC0) + payload


def hex_prefix(nibbles, is_leaf):
    flag = (2 if is_leaf else 0) + (len(nibbles) % 2)
    padded = [flag] + ([] if len(nibbles) % 2 else [0]) + list(nibbles)
    return bytes(padded[i] * 16 + padded[i + 1] for i in range(0, len(padded), 2))


def nibbles_of(key):
    return tuple(n for byte in key for n in (byte >> 4, byte & 0x0F))


class Node:
    def __init__(self, kind, path=(), value=None, child=None, children=None):
        self.kind = kind
        self.path = path
        self.value = value
        self.child = child
        self.children = children
        self.rlp = self.encode()

    def encode(self):
        if self.kind == "leaf":
            return encode_list([encode_string(hex_prefix(self.path, True)), encode_string(self.value)])
        if self.kind == "extension":
            return encode_list([encode_string(hex_prefix(self.path, False)), self.child.reference()])
        slots = [b"\x80" if c is None else c.reference() for c in self.children]
        return encode_list(slots + [b"\x80" if self.value is None else encode_string(self.value)])

    def embedded(self):
        return len(self.rlp) < HASH_LEN

    def reference(self):
        if self.embedded():
            return self.rlp
        return encode_string(keccak256(self.rlp))


def build(entries, depth):
    if len(entries) == 1:
        (path, value), = entries.items()
        return Node("leaf", path=path[depth:], value=value)
    paths = list(entries)
    shared = 0
    while all(len(p) > depth + shared and p[depth + shared] == paths[0][depth + shared] for p in paths):
        shared += 1
    if shared:
        return Node("extension", path=paths[0][depth : depth + shared], child=build(entries, depth + shared))
    groups = [dict() for _ in range(16)]
    ending = None
    for path, value in entries.items():
        if len(path) == depth:
            ending = value
        else:
            groups[path[depth]][path] = value
    return Node("branch", value=ending, children=[build(g, depth + 1) if g else None for g in groups])


class Trie:
    def __init__(self, entries):
        self.root = build({nibbles_of(k): v for k, v in entries.items()}, 0)
        self.root_hash = keccak256(self.root.rlp)
        self.nodes = []
        self.index = {}

    def node_index(self, node):
        if node.rlp not in self.index:
            self.index[node.rlp] = len(self.nodes)
            self.nodes.append(node.rlp)
        return self.index[node.rlp]

    def lookup(self, key):
        path = nibbles_of(key)
        node = self.root
        proof = [self.node_index(node)]
        features = {"root_leaf"} if node.kind == "leaf" else set()
        position = 0
        while True:
            features.add(("embedded_" if node.embedded() and node is not self.root else "hashed_") + node.kind)
            if node.rlp[0] >= 0xF8:
                features.add("long_list_node")
            if node.kind == "branch":
                child = node.children[path[position]]
                position += 1
                if child is None:
                    features.add("absent_empty_slot")
                    return proof, None, features | self.inside(node)
            else:
                parity = "odd" if len(node.path) % 2 else "even"
                features.add(f"{parity}_{node.kind}_path")
                if path[position : position + len(node.path)] != node.path:
                    features.add(f"absent_{node.kind}_divergence")
                    return proof, None, features | self.inside(node)
                position += len(node.path)
                if node.kind == "leaf":
                    if position != KEY_NIBBLES:
                        raise AssertionError("leaf reached before the key ended")
                    if len(node.value) == 1 and node.value[0] < 0x80:
                        features.add("single_byte_value")
                    if len(node.value) >= 56:
                        features.add("long_value")
                    return proof, node.value, features
                child = node.child
                features.add("extension_to_" + ("embedded" if child.embedded() else "hashed") + "_child")
            if not child.embedded():
                proof.append(self.node_index(child))
            node = child

    def inside(self, node):
        if node is not self.root and node.embedded():
            return {"absent_inside_embedded"}
        return set()


class Random:
    def __init__(self, seed):
        self.source = random.Random(seed)

    def bits(self, count):
        return self.source.getrandbits(count)

    def below(self, bound):
        width = max(1, (bound - 1).bit_length())
        while True:
            value = self.bits(width)
            if value < bound:
                return value

    def pick(self, items):
        return items[self.below(len(items))]

    def bytes(self, count):
        return self.bits(8 * count).to_bytes(count, "big") if count else b""


def with_prefix(rng, anchor, keep):
    nibbles = list(nibbles_of(anchor))
    for i in range(keep, KEY_NIBBLES):
        nibbles[i] = rng.below(16)
    return bytes(nibbles[i] * 16 + nibbles[i + 1] for i in range(0, KEY_NIBBLES, 2))


def shared_prefix(rng):
    bucket = rng.below(4)
    if bucket == 0:
        return rng.below(3)
    if bucket == 1:
        return 3 + rng.below(53)
    if bucket == 2:
        return 56 + rng.below(6)
    return 62 + rng.below(2)


def random_value(rng):
    bucket = rng.below(4)
    if bucket == 0:
        return bytes([rng.below(0x80)])
    if bucket == 1:
        return rng.bytes(1 + rng.below(4))
    if bucket == 2:
        return rng.bytes(5 + rng.below(27))
    return rng.bytes(32 + rng.below(29))


def random_entries(rng, count):
    entries = {}
    while len(entries) < count:
        if entries:
            key = with_prefix(rng, rng.pick(sorted(entries)), shared_prefix(rng))
        else:
            key = rng.bytes(HASH_LEN)
        if key not in entries:
            entries[key] = random_value(rng)
    return entries


def absent_cases(rng, trie, entries, covered):
    candidates = []
    keys = sorted(entries)
    for _ in range(ABSENT_CANDIDATES):
        key = with_prefix(rng, rng.pick(keys), rng.below(KEY_NIBBLES + 1))
        if key in entries:
            continue
        proof, value, features = trie.lookup(key)
        if value is not None:
            raise AssertionError("a key outside the map was found")
        candidates.append((key, proof, features))
    chosen = []
    seen = set()
    while candidates and len(chosen) < ABSENT_PER_TRIE:
        candidates.sort(key=lambda c: (min(covered.get(f, 0) for f in c[2]), c[0]))
        key, proof, features = candidates.pop(0)
        if key in seen:
            continue
        seen.add(key)
        for f in features:
            covered[f] = covered.get(f, 0) + 1
        chosen.append((key, proof))
    return chosen


def generate_set():
    rng = Random(SEED)
    covered = {}
    tries = []
    for t in range(TRIE_COUNT):
        count = 1 if t == 0 else 2 + rng.below(MAX_KEYS - 1)
        entries = random_entries(rng, count)
        trie = Trie(entries)
        cases = []
        for key in sorted(entries):
            proof, value, features = trie.lookup(key)
            if value != entries[key]:
                raise AssertionError("lookup returned a different value")
            for f in features:
                covered[f] = covered.get(f, 0) + 1
            cases.append({"key": "0x" + key.hex(), "value": "0x" + value.hex(), "proof": proof})
        for key, proof in absent_cases(rng, trie, entries, covered):
            cases.append({"key": "0x" + key.hex(), "value": None, "proof": proof})
        tries.append(
            {
                "root": "0x" + trie.root_hash.hex(),
                "nodes": ["0x" + n.hex() for n in trie.nodes],
                "cases": cases,
            }
        )
    missing = [f for f in FEATURES if not covered.get(f)]
    if missing:
        raise SystemExit(f"error: the set has no {', '.join(missing)}")
    unexpected = sorted(set(covered) - set(FEATURES))
    if unexpected:
        raise SystemExit(f"error: unlisted features {', '.join(unexpected)}")
    return {
        "name": NAME,
        "kind": KIND,
        "seed": SEED,
        "command": "synth_trie.py generate",
        "coverage": {f: covered[f] for f in FEATURES},
        "tries": tries,
    }


def render(fixture):
    return json.dumps(fixture, indent=1) + "\n"


def main(argv):
    if len(argv) != 2 or argv[1] not in ("generate", "check"):
        raise SystemExit(__doc__)
    text = render(generate_set())
    if argv[1] == "generate":
        OUTPUT.write_text(text)
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
    elif not OUTPUT.exists() or OUTPUT.read_text() != text:
        raise SystemExit(f"error: {OUTPUT.relative_to(ROOT)} differs from seed {SEED}")
    else:
        print(f"{OUTPUT.relative_to(ROOT)} matches seed {SEED}")


if __name__ == "__main__":
    main(sys.argv)
