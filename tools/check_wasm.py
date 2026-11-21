"""Check the committed WebAssembly verifier's integrity.

usage:

    python3 -I tools/check_wasm.py

This gate pins the browser module to this file: the committed
docs/wasm/frontier.wasm must hash to the sha256 pinned below, that hash
must match the one in the committed manifest, the manifest's compiler
line must be the pinned one, and the manifest must list every export the
page calls. Rebuilding the module (one command, in wasm/README.md) means
updating the two pins here in the same commit, which makes every module
change visible in review. What this gate cannot do is rebuild the module
from source in CI; the compiler is a pinned Rust build, and the rebuild
command exists so anyone can reproduce the bytes themselves.
"""

import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINNED_SHA256 = "59c4a54e0dbb1175dc508c221ed2610bf343f9918e677419d2a7438732ba3297"
PINNED_COMPILER = "fe 26.7.0 (2e9a011df)"


def main(argv):
    manifest = json.loads((ROOT / "docs" / "wasm" / "frontier.manifest.json").read_text())
    module = (ROOT / "docs" / "wasm" / "frontier.wasm").read_bytes()
    digest = hashlib.sha256(module).hexdigest()
    claimed = manifest["module"]["sha256"]
    if digest != PINNED_SHA256:
        raise SystemExit(f"error: frontier.wasm hashes to {digest}, this gate pins {PINNED_SHA256}")
    if digest != claimed:
        raise SystemExit(f"error: frontier.wasm hashes to {digest}, manifest claims {claimed}")
    if manifest["compiler"] != PINNED_COMPILER:
        raise SystemExit(
            f"error: manifest compiler {manifest['compiler']!r} differs from the pinned {PINNED_COMPILER!r}"
        )
    if manifest["module"]["size"] != len(module):
        raise SystemExit("error: frontier.wasm size differs from the manifest")
    names = {entry["name"] for entry in manifest["exports"]}
    needed = {"alloc", "arena_mark", "arena_release", "memory", "xmss_check", "branch_check", "trie_check"}
    missing = needed - names
    if missing:
        raise SystemExit(f"error: manifest is missing exports: {sorted(missing)}")
    print(f"frontier.wasm intact: {len(module)} bytes, built by {manifest['compiler']}")


if __name__ == "__main__":
    main(sys.argv)
