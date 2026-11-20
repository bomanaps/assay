"""Generate the post-quantum beacon state fixture from the pq spec itself.

usage, from a consensus-specs checkout on the pq branch after `make build`:

    uv run python <assay>/tools/gen_pq_fixture.py <assay>/fixtures/pq_state.json

The fixture is built from a state the executable pq specification creates,
so every byte comes from Ethereum's own draft of its post-quantum fork, not
from this repository's opinion of it. It proves facts of the new world: a
validator's XMSS public key, the new vrf_root field beside it, the whole
nine-field validator record, and the chain's genesis root, each with the
branch the new progressive-container layout produces.

The fixture records the exact spec commit it was generated against, because
the pq branch moves; regenerating against a newer commit is one rerun of
this script. Verifying the committed fixture needs no spec machinery at all:
the branches are ordinary SSZ branches that any generic walker can check
against the recorded state root, which is how this repository's CI and
tests consume it.
"""

import json
import pathlib
import subprocess
import sys


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    out = pathlib.Path(argv[1])

    from eth_consensus_specs.test.helpers.constants import MINIMAL, PQ
    from eth_consensus_specs.test.helpers.genesis import create_genesis_state
    from eth_consensus_specs.test.helpers.specs import spec_targets
    import ssz

    spec = spec_targets[MINIMAL][PQ]
    balances = [spec.MAX_EFFECTIVE_BALANCE] * 8
    state = create_genesis_state(spec, balances, activation_threshold=spec.MAX_EFFECTIVE_BALANCE)
    state_root = bytes(state.hash_tree_root())
    index = 3
    validator = state.validators[index]

    spec_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    proofs = []

    def add(name, gindex, leaf):
        branch = [bytes(node) for node in ssz.build_proof(state, gindex)]
        reconstructed = bytes(ssz.calculate_merkle_root(leaf, branch, gindex))
        if reconstructed != state_root:
            raise SystemExit(f"error: the {name} branch does not reconstruct the state root")
        proofs.append(
            {
                "field": name,
                "gindex": str(int(gindex)),
                "leaf": "0x" + leaf.hex(),
                "branch": ["0x" + node.hex() for node in branch],
            }
        )

    add(f"validators[{index}].pubkey", ssz.get_generalized_index(type(state), "validators", index, "pubkey"), bytes(validator.pubkey))
    add(f"validators[{index}].vrf_root", ssz.get_generalized_index(type(state), "validators", index, "vrf_root"), bytes(validator.vrf_root))
    add(f"validators[{index}]", ssz.get_generalized_index(type(state), "validators", index), bytes(validator.hash_tree_root()))
    add("genesis_validators_root", ssz.get_generalized_index(type(state), "genesis_validators_root"), bytes(state.genesis_validators_root))

    fixture = {
        "name": "pq_state",
        "kind": "pq_state",
        "fork": str(spec.fork),
        "preset": "minimal",
        "specCommit": spec_commit,
        "stateRoot": "0x" + state_root.hex(),
        "validatorIndex": str(index),
        "validatorCount": str(len(state.validators)),
        "validator": {
            "pubkey": "0x" + bytes(validator.pubkey).hex(),
            "vrf_root": "0x" + bytes(validator.vrf_root).hex(),
            "withdrawal_credentials": "0x" + bytes(validator.withdrawal_credentials).hex(),
            "effective_balance": str(int(validator.effective_balance)),
            "slashed": bool(validator.slashed),
            "activation_eligibility_epoch": str(int(validator.activation_eligibility_epoch)),
            "activation_epoch": str(int(validator.activation_epoch)),
            "exit_epoch": str(int(validator.exit_epoch)),
            "withdrawable_epoch": str(int(validator.withdrawable_epoch)),
        },
        "proofs": proofs,
    }
    out.write_text(json.dumps(fixture, indent=1) + "\n")
    print(f"wrote {out} against spec commit {spec_commit}")


if __name__ == "__main__":
    main(sys.argv)
