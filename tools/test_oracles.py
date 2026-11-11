import copy
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import capture_getproof
import gen_fixtures
import oracle_mpt
import oracle_ssz
import synth_trie

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def flip(text):
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def rehash(header):
    header["hash"] = "0x" + oracle_mpt.keccak256(oracle_mpt.encode_header(header)).hex()


def relink(execution):
    rehash(execution["header"])
    execution["childHeader"]["parentHash"] = execution["header"]["hash"]
    rehash(execution["childHeader"])


class TrieOracle(unittest.TestCase):
    def rejects(self, fixture, message):
        with self.assertRaises(oracle_mpt.ProofError) as caught:
            oracle_mpt.analyze(fixture)
        self.assertIn(message, str(caught.exception))

    def test_every_trie_fixture_passes(self):
        for path in sorted(FIXTURES.glob("*.json")):
            fixture = json.loads(path.read_text())
            if fixture["kind"] in oracle_mpt.MPT_KINDS:
                oracle_mpt.analyze(fixture)

    def test_corrupted_account_node(self):
        f = load("mainnet_storage_weth")
        f["proof"]["accountProof"][3] = flip(f["proof"]["accountProof"][3])
        self.rejects(f, "node 3 hashes to a value the parent does not reference")

    def test_truncated_account_proof(self):
        f = load("mainnet_storage_weth")
        f["proof"]["accountProof"].pop()
        self.rejects(f, "proof ended before a terminal node")

    def test_node_after_the_leaf(self):
        f = load("mainnet_storage_weth")
        f["proof"]["accountProof"].append(f["proof"]["accountProof"][-1])
        self.rejects(f, "nodes after the leaf")

    def test_proof_for_another_address(self):
        f = load("mainnet_storage_weth")
        f["proof"]["address"] = "0x" + "11" * 20
        self.rejects(f, "node 1 hashes to a value the parent does not reference")

    def test_slot_proofs_swapped(self):
        f = load("mainnet_storage_weth")
        a, b = f["proof"]["storageProof"][0], f["proof"]["storageProof"][1]
        a["proof"], b["proof"] = b["proof"], a["proof"]
        self.rejects(f, "node 1 hashes to a value the parent does not reference")

    def test_claimed_storage_value_differs(self):
        f = load("mainnet_storage_weth")
        f["proof"]["storageProof"][2]["value"] = "0x13"
        self.rejects(f, "decodes to 18")

    def test_claimed_account_field_differs(self):
        f = load("mainnet_storage_weth")
        f["proof"]["balance"] = "0x1"
        self.rejects(f, "decoded account disagrees with the rpc account fields")

    def test_chain_id_that_is_a_boolean(self):
        f = load("mainnet_account_eoa")
        f["chainId"] = True
        self.rejects(f, "is not a positive integer")

    def test_slot_proven_twice(self):
        f = load("mainnet_storage_weth")
        f["proof"]["storageProof"].append(copy.deepcopy(f["proof"]["storageProof"][0]))
        self.rejects(f, "is proven twice")

    def test_absent_account_claimed_present(self):
        f = load("mainnet_account_absent")
        f["proof"]["nonce"] = "0x1"
        self.rejects(f, "decoded account disagrees with the rpc account fields")

    def test_absent_account_reported_with_zero_hashes(self):
        f = load("mainnet_account_absent")
        f["proof"]["storageHash"] = "0x" + "00" * 32
        f["proof"]["codeHash"] = "0x" + "00" * 32
        self.assertFalse(oracle_mpt.analyze(f)["present"])

    def test_zero_hashes_with_a_nonzero_nonce(self):
        f = load("mainnet_account_absent")
        f["proof"]["storageHash"] = "0x" + "00" * 32
        f["proof"]["codeHash"] = "0x" + "00" * 32
        f["proof"]["nonce"] = "0x1"
        self.rejects(f, "decoded account disagrees with the rpc account fields")

    def test_present_account_reported_with_zero_hashes(self):
        f = load("mainnet_storage_weth")
        f["proof"]["nonce"] = "0x0"
        f["proof"]["balance"] = "0x0"
        f["proof"]["storageHash"] = "0x" + "00" * 32
        f["proof"]["codeHash"] = "0x" + "00" * 32
        f["proof"]["storageProof"] = []
        f["kind"] = "account"
        self.rejects(f, "decoded account disagrees with the rpc account fields")

    def test_absent_account_with_only_one_zero_hash(self):
        f = load("mainnet_account_absent")
        f["proof"]["codeHash"] = "0x" + "00" * 32
        self.rejects(f, "decoded account disagrees with the rpc account fields")

    def test_header_does_not_hash_to_its_hash(self):
        f = load("mainnet_storage_weth")
        f["header"]["stateRoot"] = flip(f["header"]["stateRoot"])
        self.rejects(f, "header hashes to")

    def test_hex_without_prefix(self):
        f = load("mainnet_storage_weth")
        f["header"]["hash"] = f["header"]["hash"][2:]
        self.rejects(f, "is not 0x-prefixed hex")

    def test_uppercase_hex(self):
        f = load("mainnet_storage_weth")
        f["header"]["hash"] = f["header"]["hash"].upper().replace("0X", "0x")
        self.rejects(f, "is not lowercase hex")

    def test_non_canonical_quantity(self):
        f = load("mainnet_storage_weth")
        f["proof"]["nonce"] = "0x01"
        self.rejects(f, "is not a canonical quantity")

    def test_kind_does_not_match_proofs(self):
        f = load("mainnet_account_eoa")
        f["kind"] = "storage"
        self.rejects(f, "does not match")

    def test_unknown_kind(self):
        f = load("mainnet_account_eoa")
        f["kind"] = "receipt"
        self.rejects(f, "not a trie fixture")

    def test_chain_id_must_be_a_positive_integer(self):
        f = load("mainnet_account_eoa")
        f["chainId"] = "1"
        self.rejects(f, "chain id")



def hp(nibbles, leaf):
    flag = (2 if leaf else 0) | (len(nibbles) & 1)
    body = [flag] + nibbles if len(nibbles) & 1 else [flag, 0] + nibbles
    return bytes(body[i] << 4 | body[i + 1] for i in range(0, len(body), 2))


def nibbles_of(data):
    return [n for byte in data for n in (byte >> 4, byte & 15)]


def leaf_node(key, value_item):
    return oracle_mpt.rlp_encode_list([oracle_mpt.rlp_encode_bytes(hp(nibbles_of(key), True)), value_item])


def synthetic_account(account_value_item, rpc=None, storage=None):
    enc = oracle_mpt.rlp_encode_bytes
    f = load("mainnet_storage_usdc")
    address = bytes.fromhex(f["proof"]["address"][2:])
    node = leaf_node(oracle_mpt.keccak256(address), account_value_item)
    f["header"]["stateRoot"] = "0x" + oracle_mpt.keccak256(node).hex()
    rehash(f["header"])
    f["proof"]["accountProof"] = ["0x" + node.hex()]
    f["proof"].update(rpc or {})
    f["proof"]["storageProof"] = storage or []
    f["kind"] = "storage" if storage else "account"
    return f


def account_with_storage(slot_value_item, claimed="0x0"):
    enc, lst = oracle_mpt.rlp_encode_bytes, oracle_mpt.rlp_encode_list
    slot = bytes(32)
    slot_node = leaf_node(oracle_mpt.keccak256(slot), slot_value_item)
    storage_root = oracle_mpt.keccak256(slot_node)
    account = enc(lst([enc(b""), enc(b""), enc(storage_root), enc(oracle_mpt.EMPTY_CODE_HASH)]))
    rpc = {
        "nonce": "0x0",
        "balance": "0x0",
        "storageHash": "0x" + storage_root.hex(),
        "codeHash": "0x" + oracle_mpt.EMPTY_CODE_HASH.hex(),
    }
    storage = [{"key": "0x" + slot.hex(), "value": claimed, "proof": ["0x" + slot_node.hex()]}]
    return synthetic_account(account, rpc, storage)


class TrieRules(unittest.TestCase):
    def raises(self, message, function, *args):
        with self.assertRaises(oracle_mpt.ProofError) as caught:
            function(*args)
        self.assertIn(message, str(caught.exception))

    def test_rlp_canonical_rules(self):
        self.raises("empty rlp input", oracle_mpt.rlp_split, b"")
        self.raises("non canonical single byte", oracle_mpt.rlp_split, bytes([0x81, 0x05]))
        self.raises("truncated length prefix", oracle_mpt.rlp_split, bytes([0xB8]))
        self.raises("non canonical length", oracle_mpt.rlp_split, bytes([0xB8, 0x01, 0x00]))
        self.raises("non canonical length", oracle_mpt.rlp_split, bytes([0xB9, 0x00, 0x40]))
        self.raises("short string", oracle_mpt.rlp_split, bytes([0x83, 0x01]))
        self.raises("short list", oracle_mpt.rlp_split, bytes([0xC3, 0x01]))
        self.raises("short item", oracle_mpt.rlp_split, bytes([0xB8, 0x38]) + bytes(10))
        self.raises("trailing bytes after rlp item", oracle_mpt.rlp_decode, bytes([0x01, 0x02]))

    def test_quantity_rules(self):
        self.raises("not a canonical quantity", oracle_mpt.to_int, "0x1_0")
        self.raises("not a canonical quantity", oracle_mpt.to_int, "0xA")
        self.raises("not a canonical quantity", oracle_mpt.to_int, "0x01")
        self.assertEqual(oracle_mpt.to_int("0x10"), 16)

    def test_walk_rejects_a_node_that_is_not_a_list(self):
        node = oracle_mpt.rlp_encode_bytes(b"\x01" * 40)
        self.raises("node 0 is not a list", oracle_mpt.walk, oracle_mpt.keccak256(node), bytes(32), [node])

    def test_hex_prefix_rules(self):
        self.raises("empty hex prefix path", oracle_mpt.decode_hex_prefix, b"")
        self.raises("bad hex prefix flag 4", oracle_mpt.decode_hex_prefix, bytes([0x40]))
        self.raises("nonzero padding nibble", oracle_mpt.decode_hex_prefix, bytes([0x01, 0x23]))

    def test_value_parsing_rules(self):
        self.raises("odd length hex", oracle_mpt.hex_bytes, "0x123")
        self.raises("is not exactly 32 bytes", oracle_mpt.hex_bytes, "0x00", 32)
        self.raises("is not a 0x-prefixed quantity", oracle_mpt.to_int, "0x")
        self.raises("is not a 0x-prefixed quantity", oracle_mpt.to_int, 7)
        self.raises("integer field is a list", oracle_mpt.rlp_int, [b"\x01"])
        self.raises("integer with leading zero", oracle_mpt.rlp_int, bytes([0x00, 0x01]))

    def walk_one(self, node, key):
        return oracle_mpt.walk(oracle_mpt.keccak256(node), key, [node])

    def test_walk_structure_rules(self):
        enc, lst = oracle_mpt.rlp_encode_bytes, oracle_mpt.rlp_encode_list
        key = bytes([0xA0]) + bytes(31)
        short_leaf = lst([enc(hp([0xA], True)), enc(b"\x01")])
        self.raises("leaf reached before the key was consumed", self.walk_one, short_leaf, key)
        branch = [enc(b"")] * 17
        branch[0xA] = enc(bytes(20))
        self.raises("child reference of length 20", self.walk_one, lst(branch), key)
        empty = lst([enc(b"")] * 17)
        self.raises("nodes after an empty branch slot", oracle_mpt.walk, oracle_mpt.keccak256(empty), key, [empty, empty])
        diverging = lst([enc(hp([0xB], True)), enc(b"\x01")])
        self.raises("nodes after a path mismatch", oracle_mpt.walk, oracle_mpt.keccak256(diverging), key, [diverging, diverging])
        full_key = lst([enc(hp(nibbles_of(key), False)), lst([enc(b"")] * 16 + [enc(b"\x05")])])
        self.raises("nodes after the branch that ends the key", oracle_mpt.walk, oracle_mpt.keccak256(full_key), key, [full_key, full_key])
        self.raises("node 0 has 3 items", self.walk_one, lst([enc(b""), enc(b""), enc(b"")]), key)
        empty_extension = lst([enc(hp([], False)), enc(bytes(32))])
        self.raises("extension with an empty path", self.walk_one, empty_extension, key)

    def test_account_leaf_rules(self):
        enc, lst = oracle_mpt.rlp_encode_bytes, oracle_mpt.rlp_encode_list
        root = enc(bytes(32))
        self.raises("account leaf value is a list", oracle_mpt.analyze, synthetic_account(lst([enc(b"\x01")])))
        self.raises("not a 4 item list", oracle_mpt.analyze, synthetic_account(enc(lst([enc(b""), enc(b""), root]))))
        lists = enc(lst([enc(b""), enc(b""), lst([]), root]))
        self.raises("account roots are lists", oracle_mpt.analyze, synthetic_account(lists))
        short = enc(lst([enc(b""), enc(b""), enc(bytes(31)), root]))
        self.raises("account roots are not 32 bytes", oracle_mpt.analyze, synthetic_account(short))

    def test_storage_leaf_rules(self):
        enc, lst = oracle_mpt.rlp_encode_bytes, oracle_mpt.rlp_encode_list
        oracle_mpt.analyze(account_with_storage(enc(enc(b"\x05")), claimed="0x5"))
        self.raises("storage leaf value is a list", oracle_mpt.analyze, account_with_storage(lst([enc(b"\x05")])))
        self.raises("storage leaf holding zero", oracle_mpt.analyze, account_with_storage(enc(enc(b""))))

    def test_empty_storage_trie_takes_no_nodes(self):
        f = load("mainnet_account_eoa")
        f["kind"] = "storage"
        f["proof"]["storageProof"] = [{"key": "0x" + "00" * 32, "value": "0x0", "proof": ["0x80"]}]
        self.raises("storage proof nodes for an empty storage trie", oracle_mpt.analyze, f)


class BeaconOracle(unittest.TestCase):
    def rejects(self, fixture, message, fixtures_dir=FIXTURES):
        with self.assertRaises(oracle_ssz.CheckError) as caught:
            oracle_ssz.analyze(fixture, fixtures_dir)
        self.assertIn(message, str(caught.exception))

    def test_beacon_fixtures_pass(self):
        oracle_ssz.analyze(load("chain_beacon"), FIXTURES)
        oracle_ssz.analyze(load("validator_beacon"), FIXTURES)

    def test_sibling_flipped(self):
        f = load("chain_beacon")
        f["proofs"][0]["branch"][5] = flip(f["proofs"][0]["branch"][5])
        self.rejects(f, "branch does not lead to the block root")

    def test_gindex_off_by_one(self):
        f = load("chain_beacon")
        f["proofs"][0]["gindex"] = str(int(f["proofs"][0]["gindex"]) + 1)
        self.rejects(f, "expected 6434")

    def test_branch_one_node_short(self):
        f = load("chain_beacon")
        f["proofs"][0]["branch"].pop()
        self.rejects(f, "branch has 11 nodes")

    def test_leaf_replaced(self):
        f = load("chain_beacon")
        f["proofs"][0]["leaf"] = flip(f["proofs"][0]["leaf"])
        self.rejects(f, "does not encode the recorded value")

    def test_wrong_consensus_version(self):
        f = load("chain_beacon")
        f["consensusVersion"] = "gloas"
        self.rejects(f, "unsupported consensus version")

    def test_header_field_changed(self):
        f = load("chain_beacon")
        f["beacon"]["header"]["proposer_index"] = str(int(f["beacon"]["header"]["proposer_index"]) + 1)
        self.rejects(f, "header fields do not hash to the block root")

    def test_proof_missing(self):
        f = load("chain_beacon")
        f["proofs"].pop()
        self.rejects(f, "missing proofs")

    def test_proof_duplicated(self):
        f = load("chain_beacon")
        f["proofs"].append(copy.deepcopy(f["proofs"][0]))
        self.rejects(f, "duplicate proof")

    def test_field_without_its_prefix(self):
        f = load("chain_beacon")
        f["proofs"][0]["field"] = f["proofs"][0]["field"].removeprefix("execution_payload.")
        self.rejects(f, "unknown proof field")

    def test_extra_key_in_a_proof(self):
        f = load("chain_beacon")
        f["proofs"][0]["note"] = "x"
        self.rejects(f, "proof keys")

    def test_extra_top_level_key(self):
        f = load("chain_beacon")
        f["extra"] = 1
        self.rejects(f, "fixture keys")

    def test_branch_node_without_prefix(self):
        f = load("chain_beacon")
        f["proofs"][1]["branch"][0] = f["proofs"][1]["branch"][0][2:]
        self.rejects(f, "is not 0x-prefixed hex")

    def test_child_does_not_name_the_block(self):
        f = load("chain_beacon")
        f["execution"]["childHeader"]["parentBeaconBlockRoot"] = flip(f["execution"]["childHeader"]["parentBeaconBlockRoot"])
        rehash(f["execution"]["childHeader"])
        self.rejects(f, "child parentBeaconBlockRoot is not the beacon block root")

    def test_child_does_not_extend_the_block(self):
        f = load("chain_beacon")
        f["execution"]["childHeader"]["parentHash"] = flip(f["execution"]["childHeader"]["parentHash"])
        rehash(f["execution"]["childHeader"])
        self.rejects(f, "child header does not extend the recorded block")

    def test_child_is_not_the_next_block(self):
        f = load("chain_beacon")
        f["execution"]["childHeader"]["number"] = hex(int(f["execution"]["childHeader"]["number"], 16) + 1)
        rehash(f["execution"]["childHeader"])
        self.rejects(f, "child header is not the next block")

    def test_execution_block_from_another_slot(self):
        f = load("chain_beacon")
        f["execution"]["header"]["timestamp"] = hex(int(f["execution"]["header"]["timestamp"], 16) + 12)
        relink(f["execution"])
        self.rejects(f, "is not the time of slot")

    def test_payload_does_not_match_the_execution_block(self):
        f = load("chain_beacon")
        f["execution"]["header"]["stateRoot"] = flip(f["execution"]["header"]["stateRoot"])
        relink(f["execution"])
        self.rejects(f, "execution_payload.state_root: leaf")

    def test_execution_header_that_does_not_hash_to_its_hash(self):
        f = load("validator_beacon")
        f["execution"]["header"]["gasUsed"] = hex(int(f["execution"]["header"]["gasUsed"], 16) + 1)
        self.rejects(f, "execution header: header hashes to")

    def test_validator_execution_block_not_named_by_the_state(self):
        f = load("validator_beacon")
        f["execution"]["header"]["stateRoot"] = flip(f["execution"]["header"]["stateRoot"])
        relink(f["execution"])
        self.rejects(f, "latest_execution_payload_header.block_hash: leaf")

    def test_child_timestamp_off_the_slot_grid(self):
        for name in ("chain_beacon", "validator_beacon"):
            f = load(name)
            child = f["execution"]["childHeader"]
            child["timestamp"] = hex(int(child["timestamp"], 16) + 7)
            rehash(child)
            self.rejects(f, "is not a later slot time")

    def test_child_timestamp_not_after_the_block(self):
        f = load("validator_beacon")
        child = f["execution"]["childHeader"]
        child["timestamp"] = f["execution"]["header"]["timestamp"]
        rehash(child)
        self.rejects(f, "is not a later slot time")

    def test_trie_links_must_not_be_empty(self):
        f = load("chain_beacon")
        f["execution"]["mptFixtures"] = []
        self.rejects(f, "must list distinct fixture names")

    def test_trie_link_must_be_a_fixture_name(self):
        f = load("chain_beacon")
        f["execution"]["mptFixtures"] = ["../fixtures/chain_storage_usdc"]
        self.rejects(f, "is not a fixture name")

    def test_trie_link_file_must_hold_that_fixture(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch_dir = pathlib.Path(scratch)
            for path in FIXTURES.glob("*.json"):
                shutil.copy(path, scratch_dir / path.name)
            shutil.copy(FIXTURES / "chain_storage_weth.json", scratch_dir / "chain_storage_copy.json")
            f = load("chain_beacon")
            f["execution"]["mptFixtures"].append("chain_storage_copy")
            self.rejects(f, "holds another fixture", scratch_dir)

    def test_listed_trie_fixture_missing(self):
        f = load("chain_beacon")
        f["execution"]["mptFixtures"] = ["nonexistent"]
        self.rejects(f, "does not exist")

    def test_listed_trie_fixture_from_another_block(self):
        f = load("chain_beacon")
        f["execution"]["mptFixtures"] = ["mainnet_storage_usdc"]
        self.rejects(f, "is from a different block")

    def test_trie_links_must_be_distinct(self):
        f = load("chain_beacon")
        f["execution"]["mptFixtures"] = ["chain_storage_usdc", "chain_storage_usdc"]
        self.rejects(f, "distinct")

    def test_validator_list_level_sibling(self):
        f = load("validator_beacon")
        proof = next(p for p in f["proofs"] if p["field"].endswith("withdrawal_credentials"))
        proof["branch"][20] = flip(proof["branch"][20])
        self.rejects(f, "branch does not lead to the block root")

    def test_validator_index_changed_with_its_names(self):
        f = load("validator_beacon")
        old = int(f["validatorIndex"])
        f["validatorIndex"] = str(old + 1)
        for proof in f["proofs"]:
            proof["field"] = proof["field"].replace(f"[{old}]", f"[{old + 1}]")
        self.rejects(f, "gindex")

    def test_every_record_field_is_bound_to_the_record_proof(self):
        changes = {
            "pubkey": lambda v: flip(v),
            "withdrawal_credentials": lambda v: flip(v),
            "effective_balance": lambda v: str(int(v) - 1000000000),
            "slashed": lambda v: not v,
            "activation_eligibility_epoch": lambda v: str(int(v) + 1),
            "activation_epoch": lambda v: str(int(v) + 1),
            "exit_epoch": lambda v: str(int(v) - 1),
            "withdrawable_epoch": lambda v: str(int(v) - 1),
        }
        self.assertEqual(set(changes), oracle_ssz.VALIDATOR_RECORD_KEYS)
        for name, change in changes.items():
            f = load("validator_beacon")
            f["validator"][name] = change(f["validator"][name])
            self.rejects(f, f"validators[{f['validatorIndex']}]: leaf")

    def test_field_proof_leaves_must_encode_the_record(self):
        for name in ("pubkey", "withdrawal_credentials", "effective_balance"):
            f = load("validator_beacon")
            proof = next(p for p in f["proofs"] if p["field"].endswith("." + name))
            proof["leaf"] = flip(proof["leaf"])
            self.rejects(f, f"{name}: leaf")

    def test_slashed_must_be_a_boolean(self):
        f = load("validator_beacon")
        f["validator"]["slashed"] = 0
        self.rejects(f, "slashed is not a boolean")

    def test_non_mainnet_genesis_root(self):
        f = load("validator_beacon")
        proof = next(p for p in f["proofs"] if p["field"] == "genesis_validators_root")
        proof["leaf"] = flip(proof["leaf"])
        self.rejects(f, "genesis_validators_root: leaf")

    def test_fork_version_proof_missing(self):
        f = load("validator_beacon")
        f["proofs"] = [p for p in f["proofs"] if p["field"] != "fork.current_version"]
        self.rejects(f, "missing proofs ['fork.current_version']")

    def test_capture_not_finalized(self):
        f = load("validator_beacon")
        f["capture"]["finalized"] = False
        self.rejects(f, "finalized canonical")

    def test_capture_not_canonical(self):
        f = load("validator_beacon")
        f["capture"]["canonical"] = False
        self.rejects(f, "finalized canonical")

    def test_capture_flags_must_be_booleans(self):
        f = load("validator_beacon")
        f["capture"] = {"finalized": 1, "canonical": 1}
        self.rejects(f, "finalized canonical")

    def test_decimal_rules(self):
        for text in ("+5", "\u0663", "05", "", 5):
            with self.assertRaises(oracle_ssz.CheckError):
                oracle_ssz.decimal(text, "value")
        self.assertEqual(oracle_ssz.decimal("0", "value"), 0)

    def test_slot_before_fulu(self):
        f = load("chain_beacon")
        f["beacon"]["header"]["slot"] = str(oracle_ssz.FULU_FORK_EPOCH * oracle_ssz.SLOTS_PER_EPOCH - 1)
        root = oracle_ssz.header_root(oracle_ssz.parse_header(f["beacon"]["header"]))
        f["beacon"]["blockRoot"] = "0x" + root.hex()
        self.rejects(f, "is before the Fulu fork")

    def test_shapes_are_checked(self):
        f = load("chain_beacon")
        f["proofs"] = {}
        self.rejects(f, "proofs is not a list")
        f = load("chain_beacon")
        f["proofs"][0]["branch"] = "0x00"
        self.rejects(f, "branch is not a list")
        f = load("chain_beacon")
        f["beacon"] = "x"
        self.rejects(f, "beacon is not an object")

    def test_range_rules(self):
        f = load("validator_beacon")
        f["validatorIndex"] = str(1 << 40)
        self.rejects(f, "outside the registry limit")
        f = load("validator_beacon")
        f["validator"]["effective_balance"] = str(1 << 64)
        self.rejects(f, "does not fit uint64")
        with self.assertRaises(oracle_ssz.CheckError) as caught:
            oracle_ssz.walk(bytes(32), 0, [])
        self.assertIn("is not positive", str(caught.exception))
        with self.assertRaises(oracle_ssz.CheckError) as caught:
            oracle_ssz.field_gindex(5, 5)
        self.assertIn("outside a 5 field container", str(caught.exception))

    def test_non_canonical_decimal(self):
        f = load("validator_beacon")
        f["validatorIndex"] = "0" + f["validatorIndex"]
        self.rejects(f, "not a canonical decimal string")

    def test_unknown_kind(self):
        f = load("chain_beacon")
        f["kind"] = "beacon_blob"
        self.rejects(f, "not a beacon fixture")


ETHEREUM_TESTS = FIXTURES / "ethereum_tests"
SECURE_VECTORS = ("hex_encoded_securetrie_test.json", "trieanyorder_secureTrie.json", "trietest_secureTrie.json")
RAW_VECTORS = ("trieanyorder.json", "trietest.json")


def vector_bytes(text):
    if text.startswith("0x"):
        return bytes.fromhex(text[2:])
    return text.encode()


def vector_entries(case, secure):
    steps = case["in"].items() if isinstance(case["in"], dict) else case["in"]
    entries = {}
    for key, value in steps:
        path = vector_bytes(key)
        if secure:
            path = synth_trie.keccak256(path)
        if value is None:
            entries.pop(path, None)
        else:
            entries[path] = vector_bytes(value)
    return entries


def vector_root(entries):
    if not entries:
        return oracle_mpt.EMPTY_STORAGE_ROOT
    return synth_trie.Trie(entries).root_hash


class EthereumTrieVectors(unittest.TestCase):
    def cases(self, names):
        for name in names:
            for label, case in json.loads((ETHEREUM_TESTS / name).read_text()).items():
                yield f"{name}:{label}", case

    def test_builder_reproduces_every_official_root(self):
        count = 0
        for label, case in self.cases(SECURE_VECTORS + RAW_VECTORS):
            entries = vector_entries(case, secure=label.split(":")[0] in SECURE_VECTORS)
            self.assertEqual(vector_root(entries), vector_bytes(case["root"]), label)
            count += 1
        self.assertEqual(count, 25)

    def test_raw_vectors_reach_extensions_embedded_nodes_and_branch_values(self):
        kinds = set()

        def visit(node, top):
            if node is None:
                return
            if not top and node.embedded():
                kinds.add("embedded_" + node.kind)
            kinds.add(node.kind)
            if node.kind == "branch":
                if node.value is not None:
                    kinds.add("branch_value")
                for child in node.children:
                    visit(child, False)
            elif node.kind == "extension":
                visit(node.child, False)

        for label, case in self.cases(RAW_VECTORS):
            entries = vector_entries(case, secure=False)
            if entries:
                visit(synth_trie.Trie(entries).root, True)
        self.assertTrue({"extension", "branch_value", "embedded_leaf", "embedded_branch"} <= kinds, kinds)

    def test_oracle_walks_every_secure_key_to_its_value(self):
        walked = 0
        for label, case in self.cases(SECURE_VECTORS):
            entries = vector_entries(case, secure=True)
            if not entries:
                continue
            trie = synth_trie.Trie(entries)
            for key, value in entries.items():
                proof, found, _ = trie.lookup(key)
                self.assertEqual(found, value, label)
                self.assertEqual(oracle_mpt.walk(trie.root_hash, key, [trie.nodes[i] for i in proof]), value, label)
                walked += 1
        self.assertGreater(walked, 30)


class CaptureInputs(unittest.TestCase):
    def test_slot_words(self):
        self.assertEqual(capture_getproof.slot_word("0"), "0x" + "0" * 64)
        self.assertEqual(capture_getproof.slot_word("0xA55A70FF"), "0x" + "0" * 56 + "a55a70ff")
        for bad in ("0xg1", "1" * 65, "12\n", ""):
            with self.assertRaises(SystemExit):
                capture_getproof.slot_word(bad)

    def test_block_arguments(self):
        self.assertEqual(capture_getproof.parse_block("26375550"), "0x192757e")
        self.assertEqual(capture_getproof.parse_block("finalized"), "finalized")
        for bad in ("0x10", "-1", "1\n", "safe"):
            with self.assertRaises(SystemExit):
                capture_getproof.parse_block(bad)

    def test_fixture_names(self):
        for good in ("chain_beacon", "a", "validator_2"):
            self.assertTrue(capture_getproof.NAME_PATTERN.fullmatch(good))
        for bad in ("1abc", "abc\n", "Abc", "a-b", "fork.current_version", ""):
            self.assertFalse(capture_getproof.NAME_PATTERN.fullmatch(bad))


class SyntheticTries(unittest.TestCase):
    def rejects(self, change, message):
        f = load("synthetic_tries")
        change(f)
        with self.assertRaises(oracle_mpt.ProofError) as caught:
            oracle_mpt.analyze_synthetic(f)
        self.assertIn(message, str(caught.exception))

    def first(self, f, present):
        return next(c for c in f["tries"][1]["cases"] if (c["value"] is not None) == present)

    def test_committed_set_passes(self):
        tries = oracle_mpt.analyze_synthetic(load("synthetic_tries"))
        self.assertEqual(len(tries), synth_trie.TRIE_COUNT)

    def test_wrong_kind(self):
        self.rejects(lambda f: f.update(kind="storage"), "not a synthetic trie fixture")

    def test_node_listed_twice(self):
        self.rejects(lambda f: f["tries"][1]["nodes"].append(f["tries"][1]["nodes"][0]), "lists a node twice")

    def test_unused_node(self):
        self.rejects(lambda f: f["tries"][1]["nodes"].append(f["tries"][2]["nodes"][0]), "lists nodes no proof uses")

    def test_repeated_key(self):
        def change(f):
            cases = f["tries"][1]["cases"]
            cases[1]["key"] = cases[0]["key"]
        self.rejects(change, "repeats a key")

    def test_empty_proof(self):
        self.rejects(lambda f: self.first(f, True).update(proof=[]), "bad proof index list")

    def test_proof_index_out_of_range(self):
        self.rejects(lambda f: self.first(f, True)["proof"].append(len(f["tries"][1]["nodes"])), "bad proof index list")

    def test_negative_proof_index(self):
        self.rejects(lambda f: self.first(f, True)["proof"].__setitem__(0, -1), "bad proof index list")

    def test_proof_index_that_is_a_bool(self):
        self.rejects(lambda f: self.first(f, True)["proof"].__setitem__(0, False), "bad proof index list")

    def test_empty_value_claimed(self):
        self.rejects(lambda f: self.first(f, True).update(value="0x"), "claims an empty value")

    def test_present_value_changed(self):
        self.rejects(lambda f: self.first(f, True).update(value="0x" + "ab" * 3), "walks to a value the fixture does not claim")

    def test_present_key_claimed_absent(self):
        self.rejects(lambda f: self.first(f, True).update(value=None), "walks to a value the fixture does not claim")

    def test_absent_key_claimed_present(self):
        self.rejects(lambda f: self.first(f, False).update(value="0x01"), "walks to a value the fixture does not claim")

    def test_proof_node_from_another_trie(self):
        def change(f):
            f["tries"][1]["nodes"][0] = f["tries"][2]["nodes"][0]
        self.rejects(change, "hashes to a value the parent does not reference")

    def test_generation_requires_every_feature(self):
        saved = synth_trie.FEATURES
        synth_trie.FEATURES = saved + ("absent_after_the_key",)
        try:
            with self.assertRaises(SystemExit) as caught:
                synth_trie.generate_set()
        finally:
            synth_trie.FEATURES = saved
        self.assertIn("has no absent_after_the_key", str(caught.exception))

    def test_generation_refuses_unlisted_features(self):
        saved = synth_trie.FEATURES
        synth_trie.FEATURES = tuple(f for f in saved if f != "embedded_extension")
        try:
            with self.assertRaises(SystemExit) as caught:
                synth_trie.generate_set()
        finally:
            synth_trie.FEATURES = saved
        self.assertIn("unlisted features embedded_extension", str(caught.exception))


class Generator(unittest.TestCase):
    def generate_from(self, mutate):
        with tempfile.TemporaryDirectory() as scratch:
            scratch_dir = pathlib.Path(scratch)
            for path in FIXTURES.glob("*.json"):
                shutil.copy(path, scratch_dir / path.name)
            mutate(scratch_dir)
            saved = gen_fixtures.FIXTURES
            gen_fixtures.FIXTURES = scratch_dir
            try:
                return gen_fixtures.expected_files()
            finally:
                gen_fixtures.FIXTURES = saved

    def test_committed_fixtures_generate(self):
        self.assertTrue(self.generate_from(lambda d: None))

    def edit(self, name, change):
        def mutate(directory):
            path = directory / f"{name}.json"
            fixture = json.loads(path.read_text())
            change(fixture)
            path.write_text(json.dumps(fixture))
        return mutate

    def refuses(self, mutate, message):
        with self.assertRaises(SystemExit) as caught:
            self.generate_from(mutate)
        self.assertIn(message, str(caught.exception))

    def test_leaf_without_prefix_is_refused(self):
        def change(f):
            proof = next(p for p in f["proofs"] if p["field"].endswith("effective_balance"))
            proof["leaf"] = proof["leaf"][2:]
        self.refuses(self.edit("validator_beacon", change), "validator_beacon.json: CheckError")
        self.refuses(self.edit("validator_beacon", change), "is not 0x-prefixed hex")

    def test_fixture_name_must_be_a_lowercase_module_name(self):
        def mutate(directory):
            fixture = json.loads((directory / "mainnet_account_eoa.json").read_text())
            fixture["name"] = "Eoa"
            (directory / "Eoa.json").write_text(json.dumps(fixture))
        self.refuses(mutate, "Eoa is not a lowercase Fe module name")

    def test_renderer_and_oracle_must_agree_on_proven_fields(self):
        saved = dict(gen_fixtures.STATE_PROOFS)
        del gen_fixtures.STATE_PROOFS["latest_execution_payload_header.block_hash"]
        try:
            self.refuses(lambda d: None, "differ from")
        finally:
            gen_fixtures.STATE_PROOFS.clear()
            gen_fixtures.STATE_PROOFS.update(saved)

    def test_unknown_kind_is_refused(self):
        self.refuses(self.edit("mainnet_account_eoa", lambda f: f.update(kind="receipt")), "unknown fixture kind")

    def test_name_must_match_the_file(self):
        self.refuses(self.edit("mainnet_account_eoa", lambda f: f.update(name="other")), "holds fixture named other")

    def test_constants_come_from_parsed_values(self):
        files = self.generate_from(lambda d: None)
        text = files[gen_fixtures.OUT_DIR / "validator_beacon.fe"]
        self.assertIn("pub(ingot) const EFFECTIVE_BALANCE: u64 = 32000000000\n", text)
        self.assertIn("pub(ingot) const BLOCK_ROOT: u256 = 0x", text)


if __name__ == "__main__":
    unittest.main()
