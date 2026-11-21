/* Build a block's receipts trie in the browser and extract proofs from it.
   The computed root must equal the header's receiptsRoot or everything is
   refused, so every encoding decision is checked against the chain itself. */

const RECEIPTS = (() => {
  /* Keccak-256, the original padding. Lanes as BigInt. */
  const ROUNDS = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
  ];
  const MASK = (1n << 64n) - 1n;
  const ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
  ];

  function rotl(value, shift) {
    if (shift === 0) return value;
    return ((value << BigInt(shift)) | (value >> BigInt(64 - shift))) & MASK;
  }

  function keccakF(state) {
    for (let round = 0; round < 24; round++) {
      const c = [];
      for (let x = 0; x < 5; x++) {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
      }
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
        for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d;
      }
      const b = new Array(25);
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROT[x][y]);
        }
      }
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          state[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }
      }
      state[0] ^= ROUNDS[round];
    }
  }

  function keccak256(bytes) {
    const rate = 136;
    const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
    padded.set(bytes);
    padded[bytes.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    const state = new Array(25).fill(0n);
    for (let block = 0; block < padded.length; block += rate) {
      for (let lane = 0; lane < rate / 8; lane++) {
        let word = 0n;
        for (let i = 7; i >= 0; i--) {
          word = (word << 8n) | BigInt(padded[block + lane * 8 + i]);
        }
        state[lane] ^= word;
      }
      keccakF(state);
    }
    const out = new Uint8Array(32);
    for (let lane = 0; lane < 4; lane++) {
      let word = state[lane];
      for (let i = 0; i < 8; i++) {
        out[lane * 8 + i] = Number(word & 0xffn);
        word >>= 8n;
      }
    }
    return out;
  }

  /* RLP and trie encoding, ported from the repository's validated builder. */

  function concatBytes(parts) {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let at = 0;
    for (const part of parts) { out.set(part, at); at += part.length; }
    return out;
  }

  function encodeLength(length, offset) {
    if (length < 56) return Uint8Array.of(offset + length);
    const bytes = [];
    let value = length;
    while (value > 0) { bytes.unshift(value & 0xff); value >>= 8; }
    return Uint8Array.from([offset + 55 + bytes.length, ...bytes]);
  }

  function encodeString(data) {
    if (data.length === 1 && data[0] < 0x80) return data;
    return concatBytes([encodeLength(data.length, 0x80), data]);
  }

  function encodeList(items) {
    const payload = concatBytes(items);
    return concatBytes([encodeLength(payload.length, 0xc0), payload]);
  }

  function hexPrefix(nibbles, isLeaf) {
    const flag = (isLeaf ? 2 : 0) + (nibbles.length % 2);
    const padded = [flag, ...(nibbles.length % 2 ? [] : [0]), ...nibbles];
    const out = new Uint8Array(padded.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = padded[2 * i] * 16 + padded[2 * i + 1];
    return out;
  }

  function nibblesOf(key) {
    const out = [];
    for (const byte of key) { out.push(byte >> 4, byte & 0x0f); }
    return out;
  }

  function uintBytes(value) {
    if (value === 0) return new Uint8Array(0);
    const bytes = [];
    let v = value;
    while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
    return Uint8Array.from(bytes);
  }

  function receiptKey(index) {
    return encodeString(uintBytes(index));
  }

  function hexBytes(text) {
    const clean = text.startsWith("0x") ? text.slice(2) : text;
    const even = clean.length % 2 ? "0" + clean : clean;
    const out = new Uint8Array(even.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(even.slice(2 * i, 2 * i + 2), 16);
    return out;
  }

  function encodeReceipt(receipt) {
    const status = parseInt(receipt.status, 16);
    const logs = receipt.logs.map((log) =>
      encodeList([
        encodeString(hexBytes(log.address)),
        encodeList(log.topics.map((topic) => encodeString(hexBytes(topic)))),
        encodeString(log.data === "0x" ? new Uint8Array(0) : hexBytes(log.data)),
      ]));
    const payload = encodeList([
      encodeString(uintBytes(status)),
      encodeString(uintBytes(parseInt(receipt.cumulativeGasUsed, 16))),
      encodeString(hexBytes(receipt.logsBloom)),
      encodeList(logs),
    ]);
    const type = parseInt(receipt.type || "0x0", 16);
    if (type === 0) return payload;
    if (type > 4) throw new Error("transaction type " + type + " is not supported yet");
    return concatBytes([Uint8Array.of(type), payload]);
  }

  function makeNode(kind, path, value, child, children) {
    const node = { kind, path, value, child, children };
    if (kind === "leaf") {
      node.rlp = encodeList([encodeString(hexPrefix(path, true)), encodeString(value)]);
    } else if (kind === "extension") {
      node.rlp = encodeList([encodeString(hexPrefix(path, false)), reference(child)]);
    } else {
      const slots = children.map((c) => (c === null ? Uint8Array.of(0x80) : reference(c)));
      slots.push(value === null ? Uint8Array.of(0x80) : encodeString(value));
      node.rlp = encodeList(slots);
    }
    return node;
  }

  function reference(node) {
    if (node.rlp.length < 32) return node.rlp;
    return encodeString(keccak256(node.rlp));
  }

  function buildNode(entries, depth) {
    if (entries.length === 1) {
      const [path, value] = entries[0];
      return makeNode("leaf", path.slice(depth), value, null, null);
    }
    let shared = 0;
    const first = entries[0][0];
    while (entries.every(([p]) => p.length > depth + shared && p[depth + shared] === first[depth + shared])) {
      shared++;
    }
    if (shared) {
      return makeNode("extension", first.slice(depth, depth + shared), null, buildNode(entries, depth + shared), null);
    }
    const groups = Array.from({ length: 16 }, () => []);
    let ending = null;
    for (const [path, value] of entries) {
      if (path.length === depth) ending = value;
      else groups[path[depth]].push([path, value]);
    }
    return makeNode("branch", null, ending, null, groups.map((g) => (g.length ? buildNode(g, depth + 1) : null)));
  }

  function buildTrie(receipts, receiptsRoot) {
    if (!receipts.length) throw new Error("the block has no receipts");
    const entries = receipts.map((receipt, position) => {
      const index = parseInt(receipt.transactionIndex, 16);
      if (index !== position) throw new Error("receipt order broken at " + position);
      return [nibblesOf(receiptKey(index)), encodeReceipt(receipt)];
    });
    const root = buildNode(entries, 0);
    const rootHash = keccak256(root.rlp);
    const expected = hexBytes(receiptsRoot);
    for (let i = 0; i < 32; i++) {
      if (rootHash[i] !== expected[i]) {
        throw new Error("computed receipts root does not equal the header's; refusing");
      }
    }
    return { root, count: receipts.length };
  }

  function prove(trie, index) {
    const path = nibblesOf(receiptKey(index));
    let node = trie.root;
    const nodes = [node.rlp];
    let position = 0;
    while (true) {
      let child;
      if (node.kind === "branch") {
        child = node.children[path[position]];
        position += 1;
        if (child === null) throw new Error("no receipt at index " + index);
      } else {
        const own = node.path;
        for (let i = 0; i < own.length; i++) {
          if (path[position + i] !== own[i]) throw new Error("no receipt at index " + index);
        }
        position += own.length;
        if (node.kind === "leaf") return nodes;
        child = node.child;
      }
      if (child.rlp.length >= 32) nodes.push(child.rlp);
      node = child;
    }
  }

  function toHex(bytes) {
    return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  return { keccak256, buildTrie, prove, toHex, hexBytes };
})();

if (typeof module !== "undefined") module.exports = RECEIPTS;
