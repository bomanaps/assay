# Adversarial trie vectors

Twelve test files for Merkle-Patricia proof verifiers. Two hold honest
proofs that a correct verifier must accept. The other ten are broken in the
exact ways that have fooled real verifiers before, and a correct verifier
must reject every one of them. The files are plain JSON with no dependency on our code, so you can use
them against a verifier written in any language.

Each vector is self-contained:

| field | meaning |
|---|---|
| `name` | the vector's identifier, equal to its filename |
| `kind` | always `trie_vector` |
| `description` | one sentence stating what the vector demonstrates |
| `root` | the trie root the proof claims to reach, 32 bytes of hex |
| `key` | the 32-byte key being proven |
| `nodes` | the proof: RLP-encoded trie nodes, root node first |
| `expect` | the required outcome, see below |
| `value` | only on `accepted_inclusion`: the exact leaf payload the proof binds |
| `lenientReading` | only on `oversized_inline_node`, see the divergence note |

## Outcomes

`expect` is one of:

- `present` means the proof is honest: accept it, and the proven value
  must equal `value` byte for byte.
- `absent` means the proof honestly shows the key is not in the trie:
  accept it as a proof of absence.
- Anything else is a rejection reason: the proof is broken and must be
  refused. The names below are our labels; your verifier passes by rejecting the
file for the matching cause, whatever it calls the error:

| reason | the defect |
|---|---|
| `path_exhausted` | the proof stops early; a known 2025 exploit made verifiers read such cut-short proofs as proof of absence |
| `trailing_nodes` | extra nodes continue after the proof already ended; padding must never change what a proof means |
| `hash_mismatch` | one byte was changed, so a node no longer hashes to the value its parent points at |
| `bad_rlp` | the node structure itself is wrong: a path longer than the key, an empty extension, a child pointer that is not 32 bytes, or an embedded child that is too large |
| `bad_hex_prefix` | the path's padding half-byte must be zero and is not; Ethereum never writes such an encoding |
| `branch_value_on_path` | a branch node stores a value even though the key keeps going past it |
| `key_not_consumed` | the proof ends at a leaf before the whole key was used, so it proves some other key |

## Running them

Against our verifier, each file is one command, and exit 0 means the
vector behaved exactly as we committed it:

```
assay verify vectors/truncated_proof.json
```

The full suite, including two self-tests that prove the harness itself
refuses a vector that lies about its expectation:

```
python3 -I tools/run_vectors.py <assay-cli-binary>
```

Against your own verifier: read each file, run your verifier on `root`,
`key` and `nodes`, and check that the two honest files are accepted with the
right result and that every other file is rejected. If your verifier accepts
any of the ten broken files, it will also accept forged proofs.

## The divergence vector

`oversized_inline_node` is the one file where correct verifiers can honestly
disagree, and its `lenientReading` field says so. Under a loose reading of
the encoding rules the proof is a valid inclusion, but Ethereum itself never
produces a node shaped like this, so a strict verifier refuses it. This
suite requires the strict answer, because accepting shapes the chain never
emits gives forgers room for no benefit in return. If your verifier accepts
this one file but rejects the other nine broken ones, it is loose rather
than broken, and you should decide which of the two you meant to build.

## Provenance

We build every file deterministically with `tools/gen_vectors.py`, using the
same node encoders that are checked against Ethereum's official trie test
vectors. CI regenerates the whole set on every push and fails if a committed
file differs from its generator, so nothing here can quietly drift. Before a
file is ever written, an independent second implementation must also refuse
to read it as a valid inclusion, with the one documented exception above.
