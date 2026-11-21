/* Build a fresh beacon anchor in the browser: fetch the newest beacon block,
   merkleize its body from the Fulu schemas, and emit the branch from the
   block root down to the execution payload's state root. The result is
   trusted only after two checks pass: the recomputed header root must equal
   the root the chain named, and the assembled branch must reconstruct it. */

const ANCHOR = (() => {
  const GENESIS_TIME = 1606824023;
  const SECONDS_PER_SLOT = 12;

  const subtle = globalThis.crypto.subtle;

  async function sha(data) {
    return new Uint8Array(await subtle.digest("SHA-256", data));
  }

  async function pair(left, right) {
    const joined = new Uint8Array(64);
    joined.set(left, 0);
    joined.set(right, 32);
    return sha(joined);
  }

  const ZERO = [Promise.resolve(new Uint8Array(32))];
  function zero(depth) {
    while (ZERO.length <= depth) {
      const previous = ZERO[ZERO.length - 1];
      ZERO.push(previous.then((node) => pair(node, node)));
    }
    return ZERO[depth];
  }

  function hex(text) {
    const clean = text.startsWith("0x") ? text.slice(2) : text;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
    return out;
  }

  function toHex(bytes) {
    return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function chunksOf(bytes) {
    const chunks = [];
    for (let at = 0; at < bytes.length; at += 32) {
      const chunk = new Uint8Array(32);
      chunk.set(bytes.subarray(at, at + 32));
      chunks.push(chunk);
    }
    if (chunks.length === 0) chunks.push(new Uint8Array(32));
    return chunks;
  }

  function depthFor(leafCount) {
    let depth = 0;
    while (1 << depth < leafCount) depth++;
    return depth;
  }

  async function merkleize(chunks, limitChunks) {
    const depth = depthFor(limitChunks === undefined ? Math.max(chunks.length, 1) : limitChunks);
    async function subtree(from, to, level) {
      if (from >= chunks.length) return zero(level);
      if (level === 0) return chunks[from];
      const mid = from + (1 << (level - 1));
      return pair(await subtree(from, Math.min(mid, to), level - 1), await subtree(mid, to, level - 1));
    }
    return subtree(0, chunks.length, depth);
  }

  function lengthChunk(value) {
    const chunk = new Uint8Array(32);
    let v = BigInt(value);
    for (let i = 0; i < 8; i++) { chunk[i] = Number(v & 0xffn); v >>= 8n; }
    return chunk;
  }

  async function mix(root, length) {
    return pair(root, lengthChunk(length));
  }

  function uintChunk(value, bytes = 8) {
    const chunk = new Uint8Array(32);
    let v = BigInt(value);
    for (let i = 0; i < bytes; i++) { chunk[i] = Number(v & 0xffn); v >>= 8n; }
    return chunk;
  }

  async function bytesRoot(bytes) {
    return merkleize(chunksOf(bytes));
  }

  async function byteListRoot(bytes, limitBytes) {
    const root = await merkleize(chunksOf(bytes).slice(0, Math.max(1, Math.ceil(bytes.length / 32))), Math.ceil(limitBytes / 32));
    return mix(bytes.length === 0 ? await merkleize([], Math.ceil(limitBytes / 32)) : root, bytes.length);
  }

  async function listRoot(roots, limit) {
    return mix(await merkleize(roots, limit), roots.length);
  }

  async function bitlistRoot(sszHex, limitBits) {
    const raw = hex(sszHex);
    let top = raw.length - 1;
    let byte = raw[top];
    let bit = 7;
    while (bit >= 0 && !(byte & (1 << bit))) bit--;
    const length = top * 8 + bit;
    const stripped = raw.slice();
    stripped[top] &= ~(1 << bit);
    const used = Math.ceil(length / 8) || 0;
    const root = await merkleize(chunksOf(stripped.subarray(0, Math.max(used, 0))), Math.ceil(limitBits / 256));
    return mix(root, length);
  }

  async function bitvectorRoot(sszHex, bits) {
    return merkleize(chunksOf(hex(sszHex)), Math.ceil(bits / 256));
  }

  async function container(roots) {
    return merkleize(roots);
  }

  async function containerTree(roots, leafCount) {
    const depth = depthFor(leafCount);
    const levels = [[]];
    for (let i = 0; i < leafCount; i++) {
      levels[0].push(i < roots.length ? roots[i] : await zero(0));
    }
    for (let level = 1; level <= depth; level++) {
      const row = [];
      for (let i = 0; i < levels[level - 1].length; i += 2) {
        row.push(await pair(levels[level - 1][i], levels[level - 1][i + 1]));
      }
      levels.push(row);
    }
    return levels;
  }

  function siblings(levels, index) {
    const out = [];
    let at = index;
    for (let level = 0; level < levels.length - 1; level++) {
      out.push(levels[level][at ^ 1]);
      at >>= 1;
    }
    return out;
  }

  /* Containers, in spec field order. */

  async function checkpointRoot(v) {
    return container([uintChunk(v.epoch), hex(v.root)]);
  }

  async function attestationDataRoot(v) {
    return container([
      uintChunk(v.slot),
      uintChunk(v.index),
      hex(v.beacon_block_root),
      await checkpointRoot(v.source),
      await checkpointRoot(v.target),
    ]);
  }

  async function indexedAttestationRoot(v) {
    return container([
      await listRoot(v.attesting_indices.map((i) => uintChunk(i)), 2048 * 64),
      await attestationDataRoot(v.data),
      await bytesRoot(hex(v.signature)),
    ]);
  }

  async function headerRootOf(h) {
    return container([
      uintChunk(h.slot),
      uintChunk(h.proposer_index),
      hex(h.parent_root),
      hex(h.state_root),
      hex(h.body_root),
    ]);
  }

  async function bodyFieldRoots(body) {
    const eth1 = await container([
      hex(body.eth1_data.deposit_root),
      uintChunk(body.eth1_data.deposit_count),
      hex(body.eth1_data.block_hash),
    ]);
    const proposerSlashings = await listRoot(
      await Promise.all(body.proposer_slashings.map(async (s) =>
        container([
          await container([await headerRootOf(s.signed_header_1.message), await bytesRoot(hex(s.signed_header_1.signature))]),
          await container([await headerRootOf(s.signed_header_2.message), await bytesRoot(hex(s.signed_header_2.signature))]),
        ]))),
      16);
    const attesterSlashings = await listRoot(
      await Promise.all(body.attester_slashings.map(async (s) =>
        container([
          await indexedAttestationRoot(s.attestation_1),
          await indexedAttestationRoot(s.attestation_2),
        ]))),
      1);
    const attestations = await listRoot(
      await Promise.all(body.attestations.map(async (a) =>
        container([
          await bitlistRoot(a.aggregation_bits, 2048 * 64),
          await attestationDataRoot(a.data),
          await bytesRoot(hex(a.signature)),
          await bitvectorRoot(a.committee_bits, 64),
        ]))),
      8);
    const deposits = await listRoot(
      await Promise.all(body.deposits.map(async (d) =>
        container([
          await merkleize(d.proof.map(hex)),
          await container([
            await bytesRoot(hex(d.data.pubkey)),
            hex(d.data.withdrawal_credentials),
            uintChunk(d.data.amount),
            await bytesRoot(hex(d.data.signature)),
          ]),
        ]))),
      16);
    const exits = await listRoot(
      await Promise.all(body.voluntary_exits.map(async (e) =>
        container([
          await container([uintChunk(e.message.epoch), uintChunk(e.message.validator_index)]),
          await bytesRoot(hex(e.signature)),
        ]))),
      16);
    const syncAggregate = await container([
      await bitvectorRoot(body.sync_aggregate.sync_committee_bits, 512),
      await bytesRoot(hex(body.sync_aggregate.sync_committee_signature)),
    ]);
    const blsChanges = await listRoot(
      await Promise.all(body.bls_to_execution_changes.map(async (c) =>
        container([
          await container([
            uintChunk(c.message.validator_index),
            await bytesRoot(hex(c.message.from_bls_pubkey)),
            await bytesRoot(hex(c.message.to_execution_address)),
          ]),
          await bytesRoot(hex(c.signature)),
        ]))),
      16);
    const kzg = await listRoot(
      await Promise.all(body.blob_kzg_commitments.map((k) => bytesRoot(hex(k)))),
      4096);
    const requests = await container([
      await listRoot(
        await Promise.all(body.execution_requests.deposits.map(async (d) =>
          container([
            await bytesRoot(hex(d.pubkey)),
            hex(d.withdrawal_credentials),
            uintChunk(d.amount),
            await bytesRoot(hex(d.signature)),
            uintChunk(d.index),
          ]))),
        8192),
      await listRoot(
        await Promise.all(body.execution_requests.withdrawals.map(async (w) =>
          container([
            await bytesRoot(hex(w.source_address)),
            await bytesRoot(hex(w.validator_pubkey)),
            uintChunk(w.amount),
          ]))),
        16),
      await listRoot(
        await Promise.all(body.execution_requests.consolidations.map(async (c) =>
          container([
            await bytesRoot(hex(c.source_address)),
            await bytesRoot(hex(c.source_pubkey)),
            await bytesRoot(hex(c.target_pubkey)),
          ]))),
        2),
    ]);
    return {
      fixed: [
        await bytesRoot(hex(body.randao_reveal)),
        eth1,
        hex(body.graffiti),
        proposerSlashings,
        attesterSlashings,
        attestations,
        deposits,
        exits,
        syncAggregate,
      ],
      blsChanges,
      kzg,
      requests,
    };
  }

  async function payloadFieldRoots(p) {
    const txs = await listRoot(
      await Promise.all(p.transactions.map((t) => byteListRoot(hex(t), 1 << 30))),
      1 << 20);
    const withdrawals = await listRoot(
      await Promise.all(p.withdrawals.map(async (w) =>
        container([
          uintChunk(w.index),
          uintChunk(w.validator_index),
          await bytesRoot(hex(w.address)),
          uintChunk(w.amount),
        ]))),
      16);
    return [
      hex(p.parent_hash),
      await bytesRoot(hex(p.fee_recipient)),
      hex(p.state_root),
      hex(p.receipts_root),
      await bytesRoot(hex(p.logs_bloom)),
      hex(p.prev_randao),
      uintChunk(p.block_number),
      uintChunk(p.gas_limit),
      uintChunk(p.gas_used),
      uintChunk(p.timestamp),
      await byteListRoot(hex(p.extra_data), 32),
      uintChunk(p.base_fee_per_gas, 32),
      hex(p.block_hash),
      txs,
      withdrawals,
      uintChunk(p.blob_gas_used),
      uintChunk(p.excess_blob_gas),
    ];
  }

  async function build(beaconBase, log, options) {
    const say = log || (() => {});
    const wanted = options && options.slot;
    const head = await fetch(beaconBase + "/eth/v1/beacon/headers/head").then((r) => r.json());
    const headSlot = Number(head.data.header.message.slot);

    let anchorSlot = wanted || headSlot - 2;
    let anchor = null;
    let tries = 0;
    while (!anchor && tries < 6 && anchorSlot <= headSlot) {
      const reply = await fetch(beaconBase + "/eth/v1/beacon/headers?slot=" + anchorSlot);
      const data = reply.ok ? await reply.json() : { data: [] };
      if (data.data && data.data.length) anchor = data.data[0];
      else if (wanted) throw new Error("slot " + anchorSlot + " holds no block");
      else { anchorSlot--; tries++; }
    }
    if (!anchor) throw new Error("no recent beacon block found");

    let childSlot = anchorSlot + 1;
    let childFound = false;
    while (!childFound && childSlot <= headSlot) {
      const reply = await fetch(beaconBase + "/eth/v1/beacon/headers?slot=" + childSlot);
      const data = reply.ok ? await reply.json() : { data: [] };
      if (data.data && data.data.length &&
          data.data[0].header.message.parent_root === anchor.root) childFound = true;
      else childSlot++;
    }
    if (!childFound) throw new Error("the anchor has no child block yet");
    say("anchored at slot " + anchorSlot + ", child at " + childSlot);

    const block = await fetch(beaconBase + "/eth/v2/beacon/blocks/" + anchor.root)
      .then((r) => r.json());
    const message = block.data.message;
    const body = message.body;
    const payload = body.execution_payload;

    const fields = await bodyFieldRoots(body);
    const payloadRoots = await payloadFieldRoots(payload);
    const payloadLevels = await containerTree(payloadRoots, 32);
    const payloadRoot = payloadLevels[5][0];

    const bodyRoots = [...fields.fixed, payloadRoot, fields.blsChanges, fields.kzg, fields.requests];
    const bodyLevels = await containerTree(bodyRoots, 16);
    const bodyRoot = bodyLevels[4][0];

    const headerFields = [
      uintChunk(message.slot),
      uintChunk(message.proposer_index),
      hex(message.parent_root),
      hex(message.state_root),
      bodyRoot,
    ];
    const headerLevels = await containerTree(headerFields, 8);
    const blockRoot = headerLevels[3][0];

    if (toHex(blockRoot) !== anchor.root) {
      throw new Error("recomputed block root " + toHex(blockRoot) + " differs from the chain's " + anchor.root);
    }
    say("block root recomputed and matches the chain");

    const bodyUp = siblings(bodyLevels, 9);
    const headerUp = siblings(headerLevels, 4);
    const branch = [...siblings(payloadLevels, 2), ...bodyUp, ...headerUp];
    const receiptsBranch = [...siblings(payloadLevels, 3), ...bodyUp, ...headerUp];

    async function walk(leaf, gindexStart, nodes) {
      let node = leaf;
      let gindex = gindexStart;
      for (const sibling of nodes) {
        node = (gindex & 1n) ? await pair(sibling, node) : await pair(node, sibling);
        gindex >>= 1n;
      }
      return toHex(node);
    }
    if (await walk(hex(payload.state_root), 6434n, branch) !== anchor.root) {
      throw new Error("the assembled state branch does not reconstruct the block root");
    }
    if (await walk(hex(payload.receipts_root), 6435n, receiptsBranch) !== anchor.root) {
      throw new Error("the assembled receipts branch does not reconstruct the block root");
    }
    say("state and receipts branches verified locally");

    return {
      timestamp: GENESIS_TIME + SECONDS_PER_SLOT * childSlot,
      header: {
        slot: Number(message.slot),
        proposer_index: Number(message.proposer_index),
        parent_root: message.parent_root,
        state_root: message.state_root,
        body_root: toHex(bodyRoot),
      },
      stateRoot: payload.state_root,
      receiptsRoot: payload.receipts_root,
      branch: branch.map(toHex),
      receiptsBranch: receiptsBranch.map(toHex),
      blockHash: payload.block_hash,
      blockNumber: Number(payload.block_number),
      blockRoot: anchor.root,
      anchorSlot,
    };
  }

  async function probe(body) {
    const a = body.attestations[0];
    const out = {};
    out.att0_bits = toHex(await bitlistRoot(a.aggregation_bits, 2048 * 64));
    out.att0_data = toHex(await attestationDataRoot(a.data));
    out.att0_cbits = toHex(await bitvectorRoot(a.committee_bits, 64));
    out.att0 = toHex(await container([
      await bitlistRoot(a.aggregation_bits, 2048 * 64),
      await attestationDataRoot(a.data),
      await bytesRoot(hex(a.signature)),
      await bitvectorRoot(a.committee_bits, 64),
    ]));
    out.kzg0 = toHex(await bytesRoot(hex(body.blob_kzg_commitments[0])));
    out.req_deposits = toHex(await listRoot([], 8192));
    out.req_withdrawals = toHex(await listRoot([], 16));
    out.req_consolidations = toHex(await listRoot([], 2));
    const tx0 = body.execution_payload.transactions[0];
    out.tx0 = toHex(await byteListRoot(hex(tx0), 1 << 30));
    out.tx0_len = (tx0.length - 2) / 2;
    return out;
  }

  return { build, toHex, hex, _internals: { bodyFieldRoots, payloadFieldRoots, probe } };
})();

if (typeof module !== "undefined") module.exports = ANCHOR;
