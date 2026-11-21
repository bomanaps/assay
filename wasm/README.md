# The browser verifier

This ingot wraps the repository's verification library for WebAssembly, so
the Run page can verify the post-quantum state, the leanXMSS vectors and
the trie attack vectors inside a visitor's browser with no network.

The repository pins Fe v26.6.0, which has no WebAssembly backend, so this
one ingot builds with a second pinned compiler: Fe master at commit
`2e9a011df`, built from source with `cargo build --release --features wasm`
in a checkout of argotorg/fe. The committed module under `docs/wasm/`
is pinned by `tools/check_wasm.py`, which CI runs: the module's bytes
must hash to the value pinned in that script, the manifest must agree,
and the manifest's compiler line must be the pinned one. CI does not
rebuild the module from source; the pins make any change visible in
review, and the rebuild below lets anyone reproduce the bytes.

Rebuild from this directory, then update the two pins in
`tools/check_wasm.py` in the same commit:

```
fe build --backend wasm --emit wasm -O 2 --out-dir out .
cp out/frontier.wasm out/frontier.manifest.json ../docs/wasm/
```

The Provenance workflow rebuilds both halves in public: it compiles this
repository with the pinned Fe release and requires the bytes on mainnet
to equal that output plus the two constructor arguments, and it builds
the pinned Fe master commit from source, rebuilds this module, and
requires the committed bytes. If a cross platform build ever produces
different bytes for the same source, the workflow run will say so and
the pin moves to the Linux build it can reproduce.

The module's answers are not taken on trust: `node wasm/test_frontier.mjs`
runs every committed vector through the module and fails on any
disagreement, and the page's own buttons recompute verdicts live against
the committed expectations.
