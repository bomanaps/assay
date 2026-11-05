# Fixtures

Raw eth_getProof captures with the block header they were proven against. Each row's command reproduces its file bit for bit given the same chain history. Run `python3 tools/capture_getproof.py verify fixtures/*.json` to recheck every state root.

| name | kind | chain id | block | block hash | state root | captured (UTC) | command |
|---|---|---|---|---|---|---|---|
| mainnet_storage_usdc | storage | 1 | 26348447 | 0x33887dc52583a19c6e75047f81feeb3c50ef93485987500871e04951a1ec3d8e | 0xad078325534fe7f7f0447dc667cc0cef23184c559bcef84faf812fe49265b058 | 2026-11-05T11:51:13+00:00 | `capture_getproof.py capture mainnet_storage_usdc 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 26348447 0x0000000000000000000000000000000000000000000000000000000000000000` |
