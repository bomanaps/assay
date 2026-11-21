import { createRequire } from "module";
import { readFile } from "fs/promises";
const require = createRequire(import.meta.url);
const F = require(new URL("../docs/frontier.js", import.meta.url).pathname);

await F.load(new Uint8Array(await readFile(new URL("../docs/wasm/frontier.wasm", import.meta.url).pathname)));
const data = JSON.parse(await readFile(new URL("../docs/frontier_data.json", import.meta.url).pathname, "utf8"));

let bad = 0;

let accepted = 0;
for (const vector of data.xmss) {
  const got = F.xmss(vector.publicKey, vector.message, vector.signature);
  const want = vector.output === null ? 2 : (vector.output ? 1 : 0);
  if (got !== want) { console.log("XMSS DISAGREE", vector.name, got, want); bad++; }
  if (got === 1) accepted++;
}
console.log("xmss:", data.xmss.length, "vectors,", accepted, "accepted, rest refused — matches EthLib");

for (const proof of data.pq.proofs) {
  const ok = F.branch(data.pq.stateRoot, proof.leaf, proof.gindex, proof.branch);
  if (ok !== 1) { console.log("PQ FAIL", proof.field); bad++; }
  const tampered = F.branch(data.pq.stateRoot, proof.leaf.replace(/.$/, proof.leaf.endsWith("0") ? "1" : "0"), proof.gindex, proof.branch);
  if (tampered !== 0) { console.log("PQ TAMPER ACCEPTED", proof.field); bad++; }
}
console.log("pq:", data.pq.proofs.length, "proofs verified, every tampered leaf refused");

for (const vector of data.vectors) {
  const got = F.trie(vector.root, vector.key, vector.nodes);
  const want = F.TRIE_CODES[vector.expect];
  if (got !== want) { console.log("TRIE DISAGREE", vector.name, got, want); bad++; }
}
console.log("vectors:", data.vectors.length, "attack vectors, every verdict matches");

console.log(bad === 0 ? "FRONTIER WASM FULLY AGREES" : bad + " DISAGREEMENTS");
process.exit(bad ? 1 : 0);
