"""Independent leanXMSS verification, checked against EthLib's own vectors.

usage:

    python3 -I tools/oracle_xmss.py check

This verifier is written from the pinned parameters of EthLib's
Cryptography/Xmss module at commit dc0581d386cab73edd70b46681ba3f529875d80c
and shares no code with it. `check` runs every vendored vector under
fixtures/xmss and fails unless this implementation produces exactly the
recorded outcome, acceptance, refusal and length rejection alike. The Fe
verifier is the third implementation of the same rules; this one exists so
the two of them can never agree by shared mistake.

The scheme, in one paragraph: a signature carries a leaf index and two
layer signatures. On each layer the verifier hashes the message with the
signature's randomizer, reads the 16-byte digest as 64 base-4 digits,
requires the last 6 digits to be zero and the first 58 to sum to exactly
106, walks each of the 58 revealed chain values the remaining steps of its
hash chain, hashes the chain ends into the key's Merkle leaf, and climbs
the 16-sibling path to the layer root. The bottom layer signs the message;
the top layer signs the bottom root; the final root must equal the public
key's. Every hash is Keccak-256 over public parameter, address and
payload, truncated to its first 16 bytes.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from oracle_mpt import keccak256

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "fixtures" / "xmss"
ETHLIB_COMMIT = "dc0581d386cab73edd70b46681ba3f529875d80c"

DIGEST_LEN = 16
MESSAGE_LEN = 32
RANDOMIZER_LEN = 16
CHAIN_LENGTH = 4
DIGITS = 64
V = 58
TARGET_SUM = 106
LAYER_HEIGHT = 16
PUB_KEY_SIZE = 32
LAYER_SIG_SIZE = RANDOMIZER_LEN + V * DIGEST_LEN + LAYER_HEIGHT * DIGEST_LEN
SIG_SIZE = 4 + 2 * LAYER_SIG_SIZE

TAU_CHAIN = 1
TAU_LEAF = 2
TAU_NODE = 3
TAU_MSG = 12


def address(tau, mu, hi, lo):
    return (
        lo.to_bytes(4, "little")
        + hi.to_bytes(3, "little")
        + bytes([tau + 32 * mu])
        + bytes(8)
    )


def layer_hi(layer, a):
    return a + (1 << 23) * layer


def th(pp, addr, payload):
    return keccak256(pp + addr + payload)[:DIGEST_LEN]


def codeword(digest):
    number = int.from_bytes(digest, "little")
    digits = [(number >> (2 * i)) & 3 for i in range(DIGITS)]
    if any(digits[V:]):
        return None
    if sum(digits[:V]) != TARGET_SUM:
        return None
    return digits[:V]


def layer_root(pp, layer, e, msg, randomizer, chains, path):
    digest = th(pp, address(TAU_MSG, 0, layer_hi(layer, 0), e), msg + randomizer)
    digits = codeword(digest)
    if digits is None:
        return None
    ends = []
    for i in range(V):
        value = chains[i]
        for mu in range(digits[i], CHAIN_LENGTH - 1):
            value = th(
                pp,
                address(TAU_CHAIN, mu, layer_hi(layer, 0), e),
                value + i.to_bytes(16, "little"),
            )
        ends.append(value)
    node = th(pp, address(TAU_LEAF, 0, layer_hi(layer, 0), e), b"".join(ends))
    for level in range(1, LAYER_HEIGHT + 1):
        sibling = path[level - 1]
        if (e >> (level - 1)) & 1:
            pair = sibling + node
        else:
            pair = node + sibling
        node = th(pp, address(TAU_NODE, 0, layer_hi(layer, level), e >> level), pair)
    return node


def parse_layer(data):
    randomizer = data[:RANDOMIZER_LEN]
    chains = [
        data[RANDOMIZER_LEN + i * DIGEST_LEN : RANDOMIZER_LEN + (i + 1) * DIGEST_LEN]
        for i in range(V)
    ]
    path_start = RANDOMIZER_LEN + V * DIGEST_LEN
    path = [
        data[path_start + i * DIGEST_LEN : path_start + (i + 1) * DIGEST_LEN]
        for i in range(LAYER_HEIGHT)
    ]
    return randomizer, chains, path


def verify(public_key, message, signature):
    if (
        len(public_key) != PUB_KEY_SIZE
        or len(message) != MESSAGE_LEN
        or len(signature) != SIG_SIZE
    ):
        return None
    root = public_key[:DIGEST_LEN]
    pp = public_key[DIGEST_LEN:]
    leaf_index = int.from_bytes(signature[:4], "little")
    bottom = parse_layer(signature[4 : 4 + LAYER_SIG_SIZE])
    top = parse_layer(signature[4 + LAYER_SIG_SIZE :])
    bottom_root = layer_root(pp, 0, leaf_index, message, *bottom)
    if bottom_root is None:
        return False
    top_root = layer_root(pp, 1, leaf_index >> LAYER_HEIGHT, bottom_root, *top)
    if top_root is None:
        return False
    return top_root == root


def parse_vector(path):
    values = {}
    for line in path.read_text().splitlines():
        text = line.strip()
        if text in ("input:",):
            continue
        key, separator, raw = text.partition(": ")
        if not separator:
            raise SystemExit(f"error: {path}: unexpected line {line!r}")
        raw = raw.strip()
        if raw.startswith("'0x") and raw.endswith("'"):
            values[key] = bytes.fromhex(raw[3:-1])
        elif raw in ("true", "false"):
            values[key] = raw == "true"
        elif raw == "null":
            values[key] = None
        else:
            raise SystemExit(f"error: {path}: unexpected value {raw!r}")
    for key in ("public_key", "message", "signature", "output"):
        if key not in values:
            raise SystemExit(f"error: {path}: missing {key}")
    return values


def check():
    cases = sorted(d for d in VECTORS.iterdir() if d.is_dir())
    if not cases:
        raise SystemExit("error: no vendored vectors under fixtures/xmss")
    failures = 0
    for case in cases:
        values = parse_vector(case / "data.yaml")
        got = verify(values["public_key"], values["message"], values["signature"])
        expected = values["output"]
        if got == expected:
            print(f"ok   {case.name}: {expected}")
        else:
            print(f"FAIL {case.name}: expected {expected}, got {got}")
            failures += 1
    if failures:
        raise SystemExit(f"error: {failures} of {len(cases)} vectors disagree")
    print(f"{len(cases)} vectors agree with EthLib at {ETHLIB_COMMIT[:12]}")


def main(argv):
    if len(argv) == 2 and argv[1] == "check":
        check()
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
