"""Run the adversarial trie vector suite through the native CLI.

usage: run_vectors.py <assay-cli-binary>

First the committed vectors are checked against their generator, so nobody
can quietly edit a vector or its expectation. Then every vector runs through
the CLI, which accepts the two honest proofs and must reject each malformed
shape for the exact reason the vector names, exit 0 per file. Finally two
self-tests prove the harness itself has teeth: a vector whose expectation is
changed to a lie, and a malformed vector stripped of its expectation, must
both be refused. The exit status is nonzero on any disagreement.
"""

import json
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import gen_vectors

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"


def run(binary, path):
    done = subprocess.run(
        [binary, "verify", str(path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return done.returncode, done.stdout + done.stderr


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    binary = str(pathlib.Path(argv[1]).resolve())
    gen_vectors.check()
    failures = 0
    paths = sorted(VECTORS.glob("*.json"))
    if len(paths) < 10:
        raise SystemExit(f"error: only {len(paths)} vectors found")
    for path in paths:
        code, output = run(binary, path)
        line = output.strip().splitlines()[-1] if output.strip() else ""
        if code != 0:
            print(f"DISAGREED {path.name}: exit {code}: {line}")
            failures += 1
        else:
            print(line)
    with tempfile.TemporaryDirectory() as scratch:
        lying = json.loads((VECTORS / "truncated_proof.json").read_text())
        lying["expect"] = "trailing_nodes"
        lie_path = pathlib.Path(scratch) / "lying_vector.json"
        lie_path.write_text(json.dumps(lying))
        code, _ = run(binary, lie_path)
        if code != 1:
            print(f"DISAGREED self-test: a lying expectation exited {code}, expected 1")
            failures += 1
        else:
            print("ok   self-test: a vector lying about its expectation is refused")
        silent = json.loads((VECTORS / "flipped_byte.json").read_text())
        del silent["expect"]
        silent_path = pathlib.Path(scratch) / "silent_vector.json"
        silent_path.write_text(json.dumps(silent))
        code, _ = run(binary, silent_path)
        if code != 2:
            print(f"DISAGREED self-test: a vector without expectation exited {code}, expected 2")
            failures += 1
        else:
            print("ok   self-test: a vector without an expectation is refused")
    if failures:
        raise SystemExit(f"{failures} vector checks disagreed")
    print(f"all {len(paths)} vectors behaved exactly as committed")


if __name__ == "__main__":
    main(sys.argv)
