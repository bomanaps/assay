"""Generate the adversarial trie vector suite.

usage: gen_vectors.py generate | check

Each vector is a committed JSON file in vectors/: a trie root, a key, a list
of proof nodes, and the exact outcome the verifier must produce. Two vectors
are honest and must be accepted; every other one is a malformed shape that
must be rejected for the named reason, including the proveth-class truncation
and the lenient-decoder shapes (oversized inline nodes, nonzero hex-prefix
padding, overlong paths) that other verifiers have been observed to accept.

Construction is deterministic: honest nodes come from synth_trie's builder,
validated against the ethereum/tests trie vectors, and each malformed shape
is assembled by explicit node surgery below, so the file shows exactly what
the attack looks like. Before writing, every malformed vector is run through
oracle_mpt's independent walker, which must never read it as a proven
inclusion; `check` regenerates everything and fails on any drift.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt
import synth_trie

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "vectors"

KEY_A = bytes.fromhex("aa" * 31 + "01")
KEY_B = bytes.fromhex("aa" * 31 + "02")
KEY_ABSENT = bytes.fromhex("bb" * 32)
VALUE_A = b"assay vector value A"
VALUE_B = b"assay vector value B"


def hexs(data):
    return "0x" + data.hex()


def base_trie():
    return synth_trie.Trie({KEY_A: VALUE_A, KEY_B: VALUE_B})


def honest_nodes(trie, key):
    proof, value, _ = trie.lookup(key)
    return [trie.nodes[i] for i in proof], value


def leaf_node(path_nibbles, value):
    return synth_trie.encode_list(
        [synth_trie.encode_string(synth_trie.hex_prefix(tuple(path_nibbles), True)), synth_trie.encode_string(value)]
    )


def branch_node(children, value):
    slots = [b"\x80" if child is None else child for child in children]
    return synth_trie.encode_list(slots + [b"\x80" if value is None else synth_trie.encode_string(value)])


def vector(name, description, root, key, nodes, expect, value=None):
    entry = {
        "name": name,
        "kind": "trie_vector",
        "description": description,
        "root": hexs(root),
        "key": hexs(key),
        "nodes": [hexs(node) for node in nodes],
        "expect": expect,
    }
    if value is not None:
        entry["value"] = hexs(value)
    return entry


def build_vectors():
    trie = base_trie()
    inclusion, value_a = honest_nodes(trie, KEY_A)
    absence, absent_value = honest_nodes(trie, KEY_ABSENT)
    if value_a != VALUE_A or absent_value is not None:
        raise SystemExit("error: the base trie does not behave as expected")
    root = trie.root_hash

    vectors = [
        vector(
            "accepted_inclusion",
            "An honest inclusion proof is accepted and the leaf value is bound exactly.",
            root, KEY_A, inclusion, "present", value=VALUE_A,
        ),
        vector(
            "accepted_absence",
            "An honest absence proof is accepted: the walk ends at a divergence the nodes themselves prove.",
            root, KEY_ABSENT, absence, "absent",
        ),
        vector(
            "truncated_proof",
            "The proveth-class attack: a proof cut short before its terminal node must never read as absence.",
            root, KEY_A, inclusion[:-1], "path_exhausted",
        ),
        vector(
            "trailing_nodes",
            "Nodes after the terminal node are refused; padding a proof must not change its meaning.",
            root, KEY_A, inclusion + [inclusion[-1]], "trailing_nodes",
        ),
        vector(
            "flipped_byte",
            "One flipped byte anywhere breaks the keccak link to the parent reference.",
            root, KEY_A, inclusion[:-1] + [inclusion[-1][:10] + bytes([inclusion[-1][10] ^ 1]) + inclusion[-1][11:]],
            "hash_mismatch",
        ),
    ]

    overlong = leaf_node(synth_trie.nibbles_of(KEY_A + b"\xcc"), VALUE_A)
    vectors.append(
        vector(
            "overlong_path",
            "A leaf path longer than the remaining key is refused instead of being silently clipped.",
            synth_trie.keccak256(overlong), KEY_A, [overlong], "bad_rlp",
        )
    )

    padded = synth_trie.encode_list(
        [
            synth_trie.encode_string(b"\x21" + KEY_A[1:]),
            synth_trie.encode_string(VALUE_A),
        ]
    )
    vectors.append(
        vector(
            "hexprefix_padding",
            "An even-length hex-prefix path with a nonzero padding nibble is non-canonical and refused.",
            synth_trie.keccak256(padded), KEY_A, [padded], "bad_hex_prefix",
        )
    )

    busy_branch = branch_node(
        [synth_trie.encode_string(synth_trie.keccak256(b"assay-child")) if i == 10 else None for i in range(16)],
        VALUE_A,
    )
    vectors.append(
        vector(
            "branch_value_on_path",
            "A branch that stores a value while the key continues past it is refused.",
            synth_trie.keccak256(busy_branch), KEY_A, [busy_branch], "branch_value_on_path",
        )
    )

    early = leaf_node(synth_trie.nibbles_of(KEY_A)[:2], VALUE_A)
    vectors.append(
        vector(
            "leaf_before_key_end",
            "A leaf that ends before the key is consumed proves a different key, not this one.",
            synth_trie.keccak256(early), KEY_A, [early], "key_not_consumed",
        )
    )

    empty_extension = synth_trie.encode_list(
        [
            synth_trie.encode_string(synth_trie.hex_prefix((), False)),
            synth_trie.encode_string(synth_trie.keccak256(b"assay-child")),
        ]
    )
    vectors.append(
        vector(
            "empty_extension",
            "An extension with an empty path adds no key material and is refused.",
            synth_trie.keccak256(empty_extension), KEY_A, [empty_extension], "bad_rlp",
        )
    )

    short_ref = branch_node(
        [synth_trie.encode_string(synth_trie.keccak256(b"assay-child")[:31]) if i == 10 else None for i in range(16)],
        None,
    )
    vectors.append(
        vector(
            "short_child_reference",
            "A child reference that is not exactly 32 bytes cannot be a keccak hash and is refused.",
            synth_trie.keccak256(short_ref), KEY_A, [short_ref], "bad_rlp",
        )
    )

    big_inline = branch_node(
        [leaf_node(synth_trie.nibbles_of(KEY_A)[1:], b"x" * 24) if i == 10 else None for i in range(16)],
        None,
    )
    oversized = vector(
        "oversized_inline_node",
        "An embedded child large enough to hold a hash reference: a lenient decoder reads it as a valid inclusion, canonical Ethereum never emits it, and Assay refuses it outright.",
        synth_trie.keccak256(big_inline), KEY_A, [big_inline], "bad_rlp",
    )
    oversized["lenientReading"] = "inclusion"
    vectors.append(oversized)

    return vectors


def oracle_guard(vectors):
    for entry in vectors:
        nodes = [bytes.fromhex(node[2:]) for node in entry["nodes"]]
        root = bytes.fromhex(entry["root"][2:])
        key = bytes.fromhex(entry["key"][2:])
        try:
            value = oracle_mpt.walk(root, key, nodes)
        except oracle_mpt.ProofError:
            value = None
        if entry["expect"] == "present":
            if value is None or hexs(value) != entry["value"]:
                raise SystemExit(f"error: the oracle does not prove {entry['name']}")
        elif entry.get("lenientReading") == "inclusion":
            if value is None:
                raise SystemExit(f"error: {entry['name']} is marked lenient-inclusion but the oracle refuses it")
        elif value is not None:
            raise SystemExit(f"error: the oracle reads {entry['name']} as a proven inclusion")


def expected_files():
    vectors = build_vectors()
    oracle_guard(vectors)
    return {OUT_DIR / f"{entry['name']}.json": json.dumps(entry, indent=1) + "\n" for entry in vectors}


def generate():
    files = expected_files()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for stale in OUT_DIR.glob("*.json"):
        if stale not in files:
            stale.unlink()
            print(f"removed {stale.relative_to(ROOT)}")
    for path, text in files.items():
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")


def check():
    files = expected_files()
    problems = 0
    readme = ROOT / "vectors" / "README.md"
    site_copy = ROOT / "docs" / "vectors.md"
    if not site_copy.exists() or site_copy.read_text() != readme.read_text():
        print("stale docs/vectors.md; copy vectors/README.md over it")
        problems += 1
    for path, text in files.items():
        if not path.exists():
            print(f"missing {path.relative_to(ROOT)}")
            problems += 1
        elif path.read_text() != text:
            print(f"stale {path.relative_to(ROOT)}")
            problems += 1
    for extra in OUT_DIR.glob("*.json"):
        if extra not in files:
            print(f"unexpected {extra.relative_to(ROOT)}")
            problems += 1
    if problems:
        raise SystemExit(1)
    print(f"{len(files)} vector files match the generator")


def main(argv):
    if len(argv) != 2 or argv[1] not in ("generate", "check"):
        raise SystemExit(__doc__)
    if argv[1] == "generate":
        generate()
    else:
        check()


if __name__ == "__main__":
    main(sys.argv)
