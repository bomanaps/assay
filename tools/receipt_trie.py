"""Build a block's receipts trie and extract verifier-shaped proofs.

The node builder is synth_trie's, validated against the ethereum/tests trie
vectors. This file adds the receipt side: canonical RLP encoding of each
receipt from eth_getBlockReceipts, typed envelopes included, rlp(index)
keys, and a lookup that follows variable-length keys. The computed root
must equal the block header's receiptsRoot, so every encoding decision is
checked against the chain itself, not against this file's own opinion.

Receipt trie keys have no prefix relationships (rlp of a canonical integer
never prefixes another), so no branch node carries a value on the path and
the walk below needs no branch-value case.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import synth_trie


def uint_bytes(value):
    if value < 0:
        raise ValueError(f"negative integer: {value}")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def receipt_key(index):
    return synth_trie.encode_string(uint_bytes(index))


def hex_field(text, name, length=None):
    if not isinstance(text, str) or not text.startswith("0x"):
        raise ValueError(f"{name} is not 0x hex: {text!r}")
    data = bytes.fromhex(text[2:].rjust((len(text) - 2 + 1) // 2 * 2, "0"))
    if length is not None and len(data) != length:
        raise ValueError(f"{name} is {len(data)} bytes, expected {length}")
    return data


def hex_uint(text, name):
    if not isinstance(text, str) or not text.startswith("0x"):
        raise ValueError(f"{name} is not 0x hex: {text!r}")
    return int(text, 16)


def encode_receipt(receipt):
    if "status" not in receipt:
        raise ValueError("receipt has no status field; pre-Byzantium blocks are not supported")
    status = hex_uint(receipt["status"], "status")
    if status not in (0, 1):
        raise ValueError(f"status is {status}, expected 0 or 1")
    cumulative = hex_uint(receipt["cumulativeGasUsed"], "cumulativeGasUsed")
    bloom = hex_field(receipt["logsBloom"], "logsBloom", 256)
    logs = []
    for log in receipt["logs"]:
        address = hex_field(log["address"], "log address", 20)
        topics = [hex_field(topic, "log topic", 32) for topic in log["topics"]]
        if len(topics) > 4:
            raise ValueError(f"log has {len(topics)} topics")
        data = hex_field(log["data"], "log data") if log["data"] != "0x" else b""
        logs.append(
            synth_trie.encode_list(
                [
                    synth_trie.encode_string(address),
                    synth_trie.encode_list([synth_trie.encode_string(t) for t in topics]),
                    synth_trie.encode_string(data),
                ]
            )
        )
    payload = synth_trie.encode_list(
        [
            synth_trie.encode_string(uint_bytes(status)),
            synth_trie.encode_string(uint_bytes(cumulative)),
            synth_trie.encode_string(bloom),
            synth_trie.encode_list(logs),
        ]
    )
    tx_type = hex_uint(receipt.get("type", "0x0"), "type")
    if tx_type == 0:
        return payload
    if tx_type > 4:
        raise ValueError(f"transaction type {tx_type} is not supported")
    return bytes([tx_type]) + payload


class ReceiptTrie:
    def __init__(self, receipts, receipts_root):
        if not receipts:
            raise ValueError("the block has no receipts; an empty trie holds no proofs")
        entries = {}
        for position, receipt in enumerate(receipts):
            index = hex_uint(receipt["transactionIndex"], "transactionIndex")
            if index != position:
                raise ValueError(f"receipt {position} claims index {index}")
            entries[receipt_key(index)] = encode_receipt(receipt)
        self.count = len(receipts)
        self.root = synth_trie.build(
            {synth_trie.nibbles_of(k): v for k, v in entries.items()}, 0
        )
        self.root_hash = synth_trie.keccak256(self.root.rlp)
        expected = hex_field(receipts_root, "receiptsRoot", 32)
        if self.root_hash != expected:
            raise ValueError(
                f"computed receipts root 0x{self.root_hash.hex()} differs from the header's 0x{expected.hex()}"
            )

    def prove(self, index):
        path = synth_trie.nibbles_of(receipt_key(index))
        node = self.root
        nodes = [node.rlp]
        position = 0
        while True:
            if node.kind == "branch":
                if position == len(path):
                    raise ValueError("a receipt key ended inside a branch; keys cannot prefix each other")
                child = node.children[path[position]]
                position += 1
                if child is None:
                    return nodes, None
            else:
                if tuple(path[position : position + len(node.path)]) != tuple(node.path):
                    return nodes, None
                position += len(node.path)
                if node.kind == "leaf":
                    if position != len(path):
                        raise ValueError("leaf reached before the key ended")
                    return nodes, node.value
                child = node.child
            if not child.embedded():
                nodes.append(child.rlp)
            node = child
