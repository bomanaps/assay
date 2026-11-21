/* Load the Fe verifier compiled to WebAssembly and drive its three checks.
   Works in the browser and in Node, so the same code that powers the page
   is the code the repository tests. */

const FRONTIER = (() => {
  let instance = null;
  let compiled = null;

  const IMPORTS = {
    env: {
      __fe_revert: () => { throw new Error("the verifier reverted"); },
    },
  };

  async function load(source) {
    const bytes = source instanceof Uint8Array
      ? source
      : new Uint8Array(await fetch(source, { cache: "no-store" }).then((r) => r.arrayBuffer()));
    compiled = await WebAssembly.compile(bytes);
    instance = new WebAssembly.Instance(compiled, IMPORTS);
    return instance;
  }

  function hexBytes(text) {
    const clean = text.startsWith("0x") ? text.slice(2) : text;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
    return out;
  }

  function place(bytes) {
    const ptr = instance.exports.alloc(bytes.length) >>> 0;
    new Uint8Array(instance.exports.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  function withArena(run) {
    const mark = instance.exports.arena_mark();
    try {
      const out = run();
      instance.exports.arena_release(mark);
      return out;
    } catch (error) {
      instance = new WebAssembly.Instance(compiled, IMPORTS);
      throw error;
    }
  }

  function xmss(publicKey, message, signature) {
    return withArena(() => {
      const pk = hexBytes(publicKey);
      const msg = hexBytes(message);
      const sig = hexBytes(signature);
      const pkPtr = place(pk);
      const msgPtr = place(msg);
      const sigPtr = place(sig);
      return Number(instance.exports.xmss_check(
        pkPtr, pk.length, msgPtr, msg.length, sigPtr, sig.length
      ));
    });
  }

  function branch(root, leaf, gindex, nodes) {
    return withArena(() => {
      const blob = new Uint8Array(72 + 32 * nodes.length);
      blob.set(hexBytes(root), 0);
      blob.set(hexBytes(leaf), 32);
      let g = BigInt(gindex);
      for (let i = 7; i >= 0; i--) { blob[64 + i] = Number(g & 0xffn); g >>= 8n; }
      nodes.forEach((node, i) => blob.set(hexBytes(node), 72 + 32 * i));
      const ptr = place(blob);
      return Number(instance.exports.branch_check(ptr, blob.length));
    });
  }

  function trie(root, key, nodes) {
    return withArena(() => {
      const encoded = nodes.map(hexBytes);
      const total = 66 + encoded.reduce((sum, n) => sum + 2 + n.length, 0);
      const blob = new Uint8Array(total);
      blob.set(hexBytes(root), 0);
      blob.set(hexBytes(key), 32);
      blob[64] = encoded.length >> 8;
      blob[65] = encoded.length & 0xff;
      let at = 66;
      for (const node of encoded) {
        blob[at] = node.length >> 8;
        blob[at + 1] = node.length & 0xff;
        blob.set(node, at + 2);
        at += 2 + node.length;
      }
      const ptr = place(blob);
      return Number(instance.exports.trie_check(ptr, blob.length));
    });
  }

  const TRIE_CODES = {
    present: 1,
    absent: 0,
    bad_rlp: 101,
    hash_mismatch: 102,
    path_exhausted: 103,
    trailing_nodes: 104,
    bad_hex_prefix: 105,
    branch_value_on_path: 106,
    depth_out_of_range: 107,
    root_mismatch: 108,
    key_not_consumed: 109,
  };

  return { load, xmss, branch, trie, TRIE_CODES };
})();

if (typeof module !== "undefined") module.exports = FRONTIER;
