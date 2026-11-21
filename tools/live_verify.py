"""Capture a fresh mainnet proof set and verify it, leaving a dated receipt.

usage: live_verify.py <assay-cli-binary>

Captures a beacon chain fixture at the chain head into a temporary directory
(the repository is never written by the capture), verifies it with the native
CLI, and on success appends one line to docs/live_log.md and updates
docs/live_stats.json with the running totals. The capture endpoints default
to the public nodes and follow RPC_URL and BEACON_URL. The exit status is
nonzero if the capture or any proof fails, and nothing is recorded then.
"""

import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOG = ROOT / "docs" / "live_log.md"
STATS = ROOT / "docs" / "live_stats.json"
LOG_HEADER = (
    "# Live verification log\n\n"
    "Each row is one successful run of `tools/live_verify.py`: a proof set captured\n"
    "fresh at the mainnet head and verified offline by the native CLI against the\n"
    "beacon block root. Rows are appended by the `live` workflow from GitHub's\n"
    "runners; a run whose proofs fail records nothing here and fails the workflow,\n"
    "so failures are visible on the Actions page, never in this table.\n\n"
    "| when (UTC) | beacon slot | execution block | beacon block root | accounts | slots |\n"
    "|---|---|---|---|---|---|\n"
)


def fail(message):
    raise SystemExit(f"FAIL {message}")


def capture(work):
    tools_copy = work / "tools"
    shutil.copytree(ROOT / "tools", tools_copy, ignore=shutil.ignore_patterns("__pycache__"))
    (work / "fixtures").mkdir()
    environment = dict(os.environ)
    environment.setdefault("RPC_URL", "https://ethereum-rpc.publicnode.com")
    environment.setdefault("BEACON_URL", "https://ethereum-beacon-api.publicnode.com")
    attempts = 0
    while True:
        attempts += 1
        done = subprocess.run(
            [sys.executable, "-I", str(tools_copy / "capture_beacon.py"), "chain"],
            capture_output=True,
            text=True,
            timeout=600,
            env=environment,
            cwd=work,
        )
        if done.returncode == 0:
            return json.loads((work / "fixtures" / "chain_beacon.json").read_text())
        if attempts >= 4:
            fail(f"capture failed after {attempts} attempts:\n{done.stdout}{done.stderr}")
        time.sleep(3)


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    binary = str(pathlib.Path(argv[1]).resolve())
    with tempfile.TemporaryDirectory() as scratch:
        work = pathlib.Path(scratch)
        chain = capture(work)
        done = subprocess.run(
            [binary, "verify", str(work / "fixtures" / "chain_beacon.json")],
            capture_output=True,
            text=True,
            timeout=600,
        )
        print(done.stdout, end="")
        if done.returncode != 0:
            fail(f"the CLI refused the fresh capture (exit {done.returncode}):\n{done.stderr}")
        verdict = re.search(r"verified: (\d+) linked accounts and (\d+) slots", done.stdout)
        if not verdict:
            fail("the CLI output holds no verdict line")
        try:
            args_tool = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(ROOT / "tools" / "gen_run_args.py"),
                    str(work / "fixtures"),
                    str(ROOT / "docs" / "run.json"),
                    "check",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            fail("run argument build timed out against the RPC")
        print(args_tool.stdout, end="")
        if args_tool.returncode != 0:
            fail(f"run argument build failed:\n{args_tool.stdout}{args_tool.stderr}")
    accounts = int(verdict.group(1))
    slots = int(verdict.group(2))
    when = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    row = "| {} | {} | {} | {} | {} | {} |\n".format(
        when,
        chain["beacon"]["header"]["slot"],
        int(chain["execution"]["header"]["number"], 16),
        chain["beacon"]["blockRoot"],
        accounts,
        slots,
    )
    existing = LOG.read_text() if LOG.exists() else LOG_HEADER
    if not existing.startswith("# Live verification log"):
        fail(f"{LOG} does not look like the live log")
    LOG.write_text(existing + row)
    stats = {"runs": 0, "accounts": 0, "slots": 0}
    if STATS.exists():
        stats = json.loads(STATS.read_text())
    stats["runs"] += 1
    stats["accounts"] += accounts
    stats["slots"] += slots
    stats["last_slot"] = int(chain["beacon"]["header"]["slot"])
    stats["last_updated"] = when
    STATS.write_text(json.dumps(stats, indent=1, sort_keys=True) + "\n")
    print(f"recorded: slot {chain['beacon']['header']['slot']}, {accounts} accounts, {slots} slots")


if __name__ == "__main__":
    main(sys.argv)
