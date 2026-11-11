"""Check trie roots against the Ethereum execution specification.

usage: spec_crosscheck.py

Needs the package from tools/requirements-spec.txt: ethereum/execution-specs
pinned to one commit, whose ethereum.merkle_patricia_trie module is the
reference trie used to define the protocol. For every trie in
fixtures/synthetic_tries.json the reference root of its present keys and
values must equal the committed root, and for every case in the ethereum/tests
trie vectors under fixtures/ethereum_tests the reference root must equal the
vector's expected root. Nothing here imports the repository's own trie code,
so this check is independent of synth_trie.py, oracle_mpt.py and the Fe
verifier. The exit status is nonzero on any disagreement.
"""

import json
import pathlib
import sys

from ethereum.merkle_patricia_trie import Trie, root, trie_set
from ethereum_types.bytes import Bytes

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
VECTORS = (
    ("hex_encoded_securetrie_test.json", True),
    ("trieanyorder_secureTrie.json", True),
    ("trietest_secureTrie.json", True),
    ("trieanyorder.json", False),
    ("trietest.json", False),
)


def vector_bytes(text):
    if text.startswith("0x"):
        return bytes.fromhex(text[2:])
    return text.encode()


def reference_root(steps, secured):
    trie = Trie(secured=secured, default=Bytes(b""))
    for key, value in steps:
        trie_set(trie, Bytes(key), Bytes(value))
    return bytes(root(trie))


def synthetic_failures():
    fixture = json.loads((FIXTURES / "synthetic_tries.json").read_text())
    failures = []
    for index, entry in enumerate(fixture["tries"]):
        steps = [
            (bytes.fromhex(case["key"][2:]), bytes.fromhex(case["value"][2:]))
            for case in entry["cases"]
            if case["value"] is not None
        ]
        if reference_root(steps, secured=False) != bytes.fromhex(entry["root"][2:]):
            failures.append(f"synthetic trie {index}")
    return len(fixture["tries"]), failures


def vector_failures():
    failures = []
    count = 0
    for name, secured in VECTORS:
        for label, case in json.loads((FIXTURES / "ethereum_tests" / name).read_text()).items():
            pairs = case["in"].items() if isinstance(case["in"], dict) else case["in"]
            steps = [(vector_bytes(key), b"" if value is None else vector_bytes(value)) for key, value in pairs]
            if reference_root(steps, secured) != vector_bytes(case["root"]):
                failures.append(f"{name}:{label}")
            count += 1
    return count, failures


def main():
    tries, synthetic = synthetic_failures()
    vectors, official = vector_failures()
    for failure in synthetic + official:
        print(f"FAIL {failure}: root differs from the execution specification")
    if synthetic or official:
        raise SystemExit(1)
    print(f"ok   {tries} synthetic tries and {vectors} ethereum/tests vectors match the execution specification")


if __name__ == "__main__":
    main()
