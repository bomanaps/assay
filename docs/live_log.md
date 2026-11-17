# Live verification log

Each row is one successful run of `tools/live_verify.py`: a proof set captured
fresh at the mainnet head and verified offline by the native CLI against the
beacon block root. Rows are appended by the `live` workflow from GitHub's
runners; a run whose proofs fail records nothing here and fails the workflow,
so failures are visible on the Actions page, never in this table.

| when (UTC) | beacon slot | execution block | beacon block root | accounts | slots |
|---|---|---|---|---|---|
| 2026-11-17T08:56:13+00:00 | 15673476 | 26433706 | 0x90d10c78097f7a1554bfce7374776ebbb2bfc8aebeb2cc892f12215f62736090 | 3 | 5 |
