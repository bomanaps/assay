# Live verification log

Each row is one successful run of `tools/live_verify.py`: a proof set captured
fresh at the mainnet head and verified offline by the native CLI against the
beacon block root. Rows are appended by the `live` workflow from GitHub's
runners; a run whose proofs fail records nothing here and fails the workflow,
so failures are visible on the Actions page, never in this table.

| when (UTC) | beacon slot | execution block | beacon block root | accounts | slots |
|---|---|---|---|---|---|
| 2026-11-17T08:56:13+00:00 | 15673476 | 26433706 | 0x90d10c78097f7a1554bfce7374776ebbb2bfc8aebeb2cc892f12215f62736090 | 3 | 5 |
| 2026-11-18T13:51:49+00:00 | 15682154 | 26442358 | 0x9293f4aac4d24e72dbff7910ea0e6946a3b99cd59ece1fe994c77f98e1b87a8a | 3 | 5 |
| 2026-11-18T20:36:28+00:00 | 15684178 | 26444382 | 0xa7441abef254d88f749cc1571a3fd095ae33295f82335d79e84f49a74ab83719 | 3 | 5 |
| 2026-11-19T07:30:29+00:00 | 15687448 | 26447639 | 0xb279129f043737d29d2f0c640cf254818dcefaef65b47650db4306bd8482eabc | 3 | 5 |
| 2026-11-19T20:42:01+00:00 | 15691405 | 26451589 | 0x2042bdffea8817c1c910a46ac3159b7a9c49fc281426bbb9d96be36b9f3bba53 | 3 | 5 |
