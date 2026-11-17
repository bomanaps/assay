"""Independent checker for receipt fixtures.

Walks the proof with oracle_mpt's trie walker, which shares no code with the
Fe verifier, decodes the proven receipt value with oracle_mpt's own RLP
decoder, and compares every claim the fixture makes (status, cumulative gas,
transaction type, log count, and the named log's address, topics, data hash
and data length) against what the proof actually proves. The fixture's own
claims are never trusted: a fixture whose claims disagree with its proof is
rejected here before it is ever written.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_mpt


class ReceiptError(Exception):
    pass


RECEIPT_KEYS = {"name", "kind", "chainId", "header", "txIndex", "proof"}
HEADER_KEYS = {"number", "hash", "receiptsRoot"}
RECEIPT_CLAIM_KEYS = {"succeeded", "cumulativeGas", "txType", "logCount"}
LOG_CLAIM_KEYS = {"index", "address", "topics", "dataHash", "dataLen"}
MAX_TX_TYPE = 4


def expect_keys(obj, required, optional, what):
    if not isinstance(obj, dict):
        raise ReceiptError(f"{what} is not an object")
    present = set(obj)
    if not required <= present:
        raise ReceiptError(f"{what} is missing {sorted(required - present)}")
    extra = present - required - optional
    if extra:
        raise ReceiptError(f"{what} holds unexpected keys {sorted(extra)}")


def receipt_key(index):
    if index == 0:
        return b"\x80"
    data = index.to_bytes((index.bit_length() + 7) // 8, "big")
    if index < 0x80:
        return data
    return bytes([0x80 + len(data)]) + data


def decode_envelope(value):
    if not value:
        raise ReceiptError("empty receipt value")
    first = value[0]
    if first >= 0xC0:
        return 0, value
    if 1 <= first <= MAX_TX_TYPE:
        return first, value[1:]
    raise ReceiptError(f"receipt value starts with byte {first:#x}")


def decode_receipt(value):
    tx_type, inner = decode_envelope(value)
    fields = oracle_mpt.rlp_decode(inner)
    if not isinstance(fields, list) or len(fields) != 4:
        raise ReceiptError("receipt is not a four-field list")
    status, cumulative, bloom, logs = fields
    if isinstance(status, list) or status not in (b"", b"\x01"):
        raise ReceiptError(f"status field {status!r} is not canonical")
    if isinstance(cumulative, list):
        raise ReceiptError("cumulative gas is a list")
    if isinstance(bloom, list) or len(bloom) != 256:
        raise ReceiptError("logsBloom is not 256 bytes")
    if not isinstance(logs, list):
        raise ReceiptError("logs is not a list")
    decoded_logs = []
    for position, log in enumerate(logs):
        if not isinstance(log, list) or len(log) != 3:
            raise ReceiptError(f"log {position} is not a three-field list")
        address, topics, data = log
        if isinstance(address, list) or len(address) != 20:
            raise ReceiptError(f"log {position} address is not 20 bytes")
        if not isinstance(topics, list) or len(topics) > 4:
            raise ReceiptError(f"log {position} topics are malformed")
        for topic in topics:
            if isinstance(topic, list) or len(topic) != 32:
                raise ReceiptError(f"log {position} holds a non-32-byte topic")
        if isinstance(data, list):
            raise ReceiptError(f"log {position} data is a list")
        decoded_logs.append({"address": address, "topics": topics, "data": data})
    return {
        "tx_type": tx_type,
        "succeeded": status == b"\x01",
        "cumulative_gas": oracle_mpt.rlp_int(cumulative),
        "logs": decoded_logs,
    }


def analyze(fixture):
    expect_keys(fixture, RECEIPT_KEYS, {"receipt", "log"}, "receipt fixture")
    if fixture["kind"] != "receipt":
        raise ReceiptError(f"kind is {fixture['kind']!r}, not receipt")
    expect_keys(fixture["header"], HEADER_KEYS, set(), "header")
    root = oracle_mpt.hex_bytes(fixture["header"]["receiptsRoot"], 32)
    index = oracle_mpt.to_int(fixture["txIndex"])
    nodes = [oracle_mpt.hex_bytes(node) for node in fixture["proof"]]
    try:
        value = oracle_mpt.walk(root, receipt_key(index), nodes)
    except oracle_mpt.ProofError as e:
        raise ReceiptError(f"proof: {e}") from None
    result = {
        "index": index,
        "number": oracle_mpt.to_int(fixture["header"]["number"]),
        "block_hash": oracle_mpt.hex_bytes(fixture["header"]["hash"], 32),
        "receipts_root": root,
        "present": value is not None,
        "nodes": nodes,
    }
    if value is None:
        if "receipt" in fixture or "log" in fixture:
            raise ReceiptError("the proof proves absence but the fixture claims a receipt")
        return result
    if "receipt" not in fixture:
        raise ReceiptError("the proof proves a receipt but the fixture claims none")
    decoded = decode_receipt(value)
    claims = fixture["receipt"]
    expect_keys(claims, RECEIPT_CLAIM_KEYS, set(), "receipt claims")
    if decoded["succeeded"] != (oracle_mpt.to_int(claims["succeeded"]) == 1):
        raise ReceiptError("claimed status disagrees with the proven receipt")
    if decoded["cumulative_gas"] != oracle_mpt.to_int(claims["cumulativeGas"]):
        raise ReceiptError("claimed cumulative gas disagrees with the proven receipt")
    if decoded["tx_type"] != oracle_mpt.to_int(claims["txType"]):
        raise ReceiptError("claimed transaction type disagrees with the proven receipt")
    if len(decoded["logs"]) != oracle_mpt.to_int(claims["logCount"]):
        raise ReceiptError("claimed log count disagrees with the proven receipt")
    result["receipt"] = decoded
    if "log" in fixture:
        log_claims = fixture["log"]
        expect_keys(log_claims, LOG_CLAIM_KEYS, set(), "log claims")
        log_index = oracle_mpt.to_int(log_claims["index"])
        if log_index >= len(decoded["logs"]):
            raise ReceiptError(f"log {log_index} does not exist in the proven receipt")
        log = decoded["logs"][log_index]
        if log["address"] != oracle_mpt.hex_bytes(log_claims["address"], 20):
            raise ReceiptError("claimed log address disagrees with the proven log")
        claimed_topics = [oracle_mpt.hex_bytes(t, 32) for t in log_claims["topics"]]
        if log["topics"] != claimed_topics:
            raise ReceiptError("claimed topics disagree with the proven log")
        if oracle_mpt.keccak256(log["data"]) != oracle_mpt.hex_bytes(log_claims["dataHash"], 32):
            raise ReceiptError("claimed data hash disagrees with the proven log")
        if len(log["data"]) != oracle_mpt.to_int(log_claims["dataLen"]):
            raise ReceiptError("claimed data length disagrees with the proven log")
        result["log_index"] = log_index
    return result
