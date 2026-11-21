"""Pack the frontier section's data for the site, with a drift gate.

usage:

    python3 -I tools/gen_frontier.py generate
    python3 -I tools/gen_frontier.py check

The Run page's frontier section verifies the post-quantum state, the
leanXMSS vectors and the trie attack vectors in the visitor's browser.
Browsers can only load files under docs/, so this tool packs the committed
originals into docs/frontier_data.json. `check` fails when the pack no
longer matches the originals, and CI runs it, so the site can never show
different data than the tests verify.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import oracle_xmss

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "frontier_data.json"


def packed():
    pq = json.loads((ROOT / "fixtures" / "pq_state.json").read_text())

    xmss = []
    for case in sorted(d for d in oracle_xmss.VECTORS.iterdir() if d.is_dir()):
        values = oracle_xmss.parse_vector(case / "data.yaml")
        xmss.append(
            {
                "name": case.name,
                "publicKey": "0x" + values["public_key"].hex(),
                "message": "0x" + values["message"].hex(),
                "signature": "0x" + values["signature"].hex(),
                "output": values["output"],
            }
        )

    vectors = []
    for path in sorted((ROOT / "vectors").glob("*.json")):
        vectors.append(json.loads(path.read_text()))

    evidence = json.loads((ROOT / "docs" / "frame_evidence.json").read_text())
    evidence.pop("rawSignedFrameTx", None)

    return {
        "pq": pq,
        "xmss": xmss,
        "vectors": vectors,
        "frames": evidence,
    }


def main(argv):
    if len(argv) != 2 or argv[1] not in ("generate", "check"):
        raise SystemExit(__doc__)
    text = json.dumps(packed(), indent=None, separators=(",", ":")) + "\n"
    if argv[1] == "generate":
        OUT.write_text(text)
        print(f"wrote {OUT}: {len(text)} bytes")
    else:
        if not OUT.exists() or OUT.read_text() != text:
            raise SystemExit("stale docs/frontier_data.json; rerun gen_frontier.py generate")
        print("frontier data matches the committed originals")


if __name__ == "__main__":
    main(sys.argv)
