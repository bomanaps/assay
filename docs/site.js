const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function observe(selector, handler) {
  const targets = document.querySelectorAll(selector);
  if (!("IntersectionObserver" in window)) {
    targets.forEach((target) => handler(target));
    return;
  }
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        handler(entry.target);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.25 });
  targets.forEach((target) => observer.observe(target));
}

observe(".reveal", (target) => target.classList.add("in-view"));

function countUp(element, value) {
  if (reduced || value === 0) {
    element.textContent = value.toLocaleString("en-US");
    return;
  }
  const start = performance.now();
  const duration = 1200;
  function frame(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = Math.round(value * eased).toLocaleString("en-US");
    if (progress < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function ago(iso) {
  const seconds = (Date.now() - Date.parse(iso)) / 1000;
  if (!isFinite(seconds)) return "unknown";
  if (seconds < 90 * 60) return Math.max(1, Math.round(seconds / 60)) + " min ago";
  return Math.round(seconds / 3600) + " h ago";
}

async function loadStats() {
  const response = await fetch("live_stats.json", { cache: "no-store" });
  const stats = await response.json();
  observe("#stat-runs", (el) => countUp(el, stats.runs));
  observe("#stat-accounts", (el) => countUp(el, stats.accounts));
  observe("#stat-slots", (el) => countUp(el, stats.slots));
  document.getElementById("last-slot").textContent = stats.last_slot.toLocaleString("en-US");
  document.getElementById("last-when").textContent = ago(stats.last_updated);
  const hours = (Date.now() - Date.parse(stats.last_updated)) / 3600000;
  if (hours > 7) {
    document.querySelector(".heartbeat .pulse").classList.add("stale");
  }
  const log = await fetch("live_log.md", { cache: "no-store" }).then((r) => r.text());
  const rows = log.split("\n").filter((line) => /^\| 2/.test(line));
  drawSparkline(rows.length);
  const latest = rows[rows.length - 1];
  if (latest) {
    const cells = latest.split("|").map((cell) => cell.trim());
    document.getElementById("readout").innerHTML =
      "when      <b>" + cells[1] + "</b>\n" +
      "slot      <b>" + cells[2] + "</b>\n" +
      "block     <b>" + cells[3] + "</b>\n" +
      "root      <b>" + cells[4].slice(0, 24) + "…</b>\n" +
      "accounts  <b>" + cells[5] + "</b>   slots  <b>" + cells[6] + "</b>\n" +
      "status    <span class=\"pass\">PASS</span>";
  }
}

function drawSparkline(count) {
  const svg = document.getElementById("spark");
  if (!svg || count < 1) return;
  const width = 600;
  const height = 72;
  const points = [];
  for (let i = 0; i < count; i++) {
    const x = count === 1 ? width / 2 : (i / (count - 1)) * width;
    const y = height - 8 - ((i + 1) / count) * (height - 20);
    points.push(x + "," + y);
  }
  svg.innerHTML =
    "<polyline fill=\"none\" stroke=\"#ffb224\" stroke-width=\"2\" points=\"" + points.join(" ") + "\"/>" +
    points.map((p) => {
      const [x, y] = p.split(",");
      return "<circle cx=\"" + x + "\" cy=\"" + y + "\" r=\"3\" fill=\"#ffb224\"/>";
    }).join("");
}

function colorLine(line) {
  const safe = line.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  if (safe.startsWith("$")) return "<span class=\"prompt\">" + safe + "</span>";
  if (safe.startsWith("ok")) return "<span class=\"ok\">" + safe + "</span>";
  if (safe.startsWith("anchor")) return "<span class=\"anchor-line\">" + safe + "</span>";
  if (safe.startsWith("verified")) return "<span class=\"verdict\">" + safe + "</span>";
  return safe;
}

async function typeTranscript(pre, path) {
  const text = await fetch(path, { cache: "no-store" }).then((r) => r.text());
  const lines = text.trimEnd().split("\n");
  pre.innerHTML = "";
  if (reduced) {
    pre.innerHTML = lines.map(colorLine).join("\n");
    return;
  }
  let index = 0;
  function next() {
    if (index >= lines.length) return;
    pre.innerHTML += (index ? "\n" : "") + colorLine(lines[index]);
    pre.scrollTop = pre.scrollHeight;
    index += 1;
    setTimeout(next, 120);
  }
  next();
}

observe("#hero-terminal", (pre) => typeTranscript(pre, "transcripts/fork.txt"));

const tabPanel = document.getElementById("tab-terminal");
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((other) => other.classList.remove("active"));
    tab.classList.add("active");
    typeTranscript(tabPanel, tab.dataset.src);
  });
});
observe("#tab-terminal", (pre) => typeTranscript(pre, "transcripts/cli.txt"));

const PLAYER_STEPS = [
  {
    title: "A claim arrives",
    text: "A caller submits a timestamp, five beacon header fields, and the SSZ and trie proofs. None of it is trusted yet: every byte could be a lie, and the next six steps are what stops that.",
    changed: ["nothing trusted", "proof data is just bytes"],
    trust: "—", links: 0, verdict: "—",
    active: { nodes: ["n-caller"], edges: ["e-call"] }, done: { nodes: [], edges: [] }
  },
  {
    title: "Anchor on the beacon root",
    text: "The contract staticcalls the genuine EIP-4788 ring buffer at 0x000F…ac02 with the timestamp and requires exactly 32 bytes back. That root, written by the chain itself, is the only trusted input.",
    changed: ["+ one trusted 32-byte root", "wrong timestamp reverts"],
    trust: "32 bytes", links: 0, verdict: "—",
    active: { nodes: ["n-prover", "n-ring"], edges: ["e-ring"] }, done: { nodes: ["n-caller"], edges: ["e-call"] }
  },
  {
    title: "The header must hash to it",
    text: "The five submitted header fields are merkleized and must equal the anchored root, and only Fulu-era slots are accepted. A header that lies about slot, proposer or any root no longer matches.",
    changed: ["header bound to the anchor", "wrong-era slots refused"],
    trust: "32 bytes", links: 1, verdict: "—",
    active: { nodes: ["n-header"], edges: ["e-anchor"] }, done: { nodes: ["n-caller", "n-prover", "n-ring"], edges: ["e-call", "e-ring"] }
  },
  {
    title: "An SSZ branch proves the state root",
    text: "Twelve sibling hashes at generalized index 6434, computed at compile time, link the execution payload's state root into the proven header. Each level is one hash: break any sibling and the chain snaps.",
    changed: ["+ execution state root proven", "gindex fixed by const fn"],
    trust: "32 bytes", links: 2, verdict: "—",
    active: { nodes: ["n-ssz"], edges: ["e-header"] }, done: { nodes: ["n-caller", "n-prover", "n-ring", "n-header"], edges: ["e-call", "e-ring", "e-anchor"] }
  },
  {
    title: "Trie walks prove account and slot",
    text: "Under that state root, canonical-only RLP trie walks prove the account, then the storage slot, every node bound by its keccak hash. The same walk with variable-length keys proves receipts and event logs under the block's receipts root, and absence is proven the same way, so a cut-short proof can never read as zero.",
    changed: ["+ account proven", "+ slot value proven", "+ receipts and logs provable", "non-canonical nodes rejected"],
    trust: "32 bytes", links: 4, verdict: "—",
    active: { nodes: ["n-trie", "n-slot"], edges: ["e-ssz", "e-trie"] }, done: { nodes: ["n-caller", "n-prover", "n-ring", "n-header", "n-ssz"], edges: ["e-call", "e-ring", "e-anchor", "e-header"] }
  },
  {
    title: "Verdict",
    text: "The slot value comes back on-chain, or the native CLI prints its verified line from the identical Fe code. Everything shown descends from one root by nothing but hashes.",
    changed: ["slot value returned", "same result on both backends"],
    trust: "32 bytes", links: 4, verdict: "PASS",
    active: { nodes: ["n-verdict"], edges: ["e-out"] }, done: { nodes: ["n-caller", "n-prover", "n-ring", "n-header", "n-ssz", "n-trie", "n-slot"], edges: ["e-call", "e-ring", "e-anchor", "e-header", "e-ssz", "e-trie"] }
  },
  {
    title: "Flip one word and it dies",
    text: "Tamper with a single branch word and the first recomputed hash no longer matches: the contract reverts, the CLI refuses. This exact tamper runs in the fork demo above, on a real mainnet fork.",
    changed: ["one flipped word", "first hash mismatch", "call reverts"],
    trust: "32 bytes", links: 0, verdict: "REVERT",
    bad: true,
    active: { nodes: [], edges: [] }, done: { nodes: ["n-caller", "n-prover", "n-ring"], edges: ["e-call", "e-ring"] }
  }
];

const playerRoot = document.querySelector(".player");
if (playerRoot) {
  const allNodes = Array.from(playerRoot.querySelectorAll(".pnode"));
  const allEdges = Array.from(playerRoot.querySelectorAll(".pedge"));
  const dots = document.getElementById("p-dots");
  PLAYER_STEPS.forEach((_, i) => {
    const dot = document.createElement("button");
    dot.className = "pdot";
    dot.type = "button";
    dot.setAttribute("aria-label", "step " + (i + 1));
    dot.addEventListener("click", () => renderStep(i));
    dots.appendChild(dot);
  });
  let current = 0;

  function renderStep(index) {
    current = Math.max(0, Math.min(PLAYER_STEPS.length - 1, index));
    const step = PLAYER_STEPS[current];
    allNodes.forEach((n) => n.classList.remove("active", "done", "bad"));
    allEdges.forEach((e) => e.classList.remove("active", "done", "bad"));
    step.done.nodes.forEach((id) => document.getElementById(id).classList.add("done"));
    step.done.edges.forEach((id) => document.getElementById(id).classList.add("done"));
    step.active.nodes.forEach((id) => document.getElementById(id).classList.add(step.bad ? "bad" : "active"));
    step.active.edges.forEach((id) => document.getElementById(id).classList.add(step.bad ? "bad" : "active"));
    if (step.bad) {
      ["n-header", "n-ssz", "n-trie", "n-slot", "n-verdict"].forEach((id) => document.getElementById(id).classList.add("bad"));
      ["e-anchor", "e-header", "e-ssz", "e-trie", "e-out"].forEach((id) => document.getElementById(id).classList.add("bad"));
    }
    document.getElementById("n-verdict-text").textContent =
      step.verdict === "—" ? "verdict" : "verdict: " + step.verdict;
    document.getElementById("p-kicker").textContent = "step " + (current + 1) + " of " + PLAYER_STEPS.length;
    document.getElementById("p-title").textContent = step.title;
    document.getElementById("p-text").textContent = step.text;
    document.getElementById("p-changed").innerHTML = step.changed.map((line) => "<li>" + line + "</li>").join("");
    const trust = document.getElementById("chip-trust");
    trust.textContent = step.trust;
    trust.className = "chip-value" + (step.trust === "—" ? "" : " gold");
    document.getElementById("chip-links").textContent = step.links + " / 4";
    const verdict = document.getElementById("chip-verdict");
    verdict.textContent = step.verdict;
    verdict.className = "chip-value" + (step.verdict === "PASS" ? " good" : step.verdict === "REVERT" ? " bad" : "");
    document.getElementById("p-back").disabled = current === 0;
    document.getElementById("p-next").disabled = current === PLAYER_STEPS.length - 1;
    Array.from(dots.children).forEach((dot, i) => {
      dot.classList.toggle("on", i === current);
      dot.classList.toggle("past", i < current);
    });
  }

  document.getElementById("p-back").addEventListener("click", () => renderStep(current - 1));
  document.getElementById("p-next").addEventListener("click", () => renderStep(current + 1));
  document.getElementById("p-replay").addEventListener("click", () => renderStep(0));
  document.addEventListener("keydown", (event) => {
    if (event.target.closest("input, textarea")) return;
    if (event.key === "ArrowRight") renderStep(current + 1);
    if (event.key === "ArrowLeft") renderStep(current - 1);
    if (event.key === "r" || event.key === "R") renderStep(0);
  });

  const deepLink = location.hash.match(/^#how-(\d)$/);
  renderStep(deepLink ? Number(deepLink[1]) - 1 : 0);
}

const copyButton = document.getElementById("copy-run");
if (copyButton) {
  copyButton.addEventListener("click", async () => {
    const commands = document.getElementById("run-commands").textContent;
    try {
      await navigator.clipboard.writeText(commands);
      copyButton.textContent = "copied";
      copyButton.classList.add("done");
      setTimeout(() => {
        copyButton.textContent = "copy";
        copyButton.classList.remove("done");
      }, 1800);
    } catch {
      copyButton.textContent = "select and copy above";
    }
  });
}

const FIXTURE_NOTES = {
  mpt_account: "Proves a real mainnet account record, its nonce, balance, storage root and code hash, under a captured state root through keccak-linked canonical RLP nodes. Pure EVM computation, so Fe's tight walk beats the general-purpose Solidity trie library outright.",
  mpt_storage: "Proves one storage slot value under the account's own storage root with the same canonical-only walk. Same shape of work, same shape of win.",
  ssz_payload: "Proves the execution payload's state root inside a beacon block through a 12-level SSZ branch. Nearly all of the gas is the SHA-256 precompile, which both sides pay identically, so parity is the expected result.",
  ssz_payload_multi: "Proves all four execution payload fields at once with one deduplicated 14-helper multiproof: 17 hashes instead of 48, so the whole payload costs about what a single branch used to. The Solidity column runs four separate verifies, because no multiproof exists in the vendored library.",
  ssz_validator: "Proves a whole 8-field validator record at its registry position, about 50 hash levels deep. Both sides hash the same tree; the remaining gap is bookkeeping around the hashing, and it is shown rather than hidden."
};

const END_TO_END = [
  { name: "proveStorage", gas: 450267, detail: "live USDC slot from the beacon root" },
  { name: "proveValidator", gas: 38158, detail: "whole validator record" }
];

async function loadGas() {
  const text = await fetch("gas_benchmark.csv", { cache: "no-store" }).then((r) => r.text());
  const rows = text.trim().split("\n").slice(1).map((line) => line.split(","));
  const verifies = rows.filter((row) => row[1] === "verify");
  const best = Math.min(...verifies.map((row) => Number(row[8])));
  document.getElementById("gchip-best").textContent = best.toFixed(1) + "%";
  document.getElementById("gchip-count").textContent = String(verifies.length);
  const max = Math.max(...verifies.flatMap((row) => [Number(row[2]), Number(row[7])]));
  const groups = document.getElementById("gas-groups");
  groups.innerHTML = verifies.map((row, index) => {
    const fe = Number(row[2]);
    const sol = Number(row[7]);
    const delta = Number(row[8]);
    const cls = delta < 0 ? "good" : "bad";
    const sign = delta > 0 ? "+" : "";
    return (
      "<div class=\"ggroup\" data-fixture=\"" + row[0] + "\">" +
      "<button class=\"ghead\" type=\"button\" aria-expanded=\"false\" data-index=\"" + index + "\">" +
      "<span class=\"gchev\">›</span><span class=\"gname\">" + row[0] + "</span>" +
      "<span class=\"gpill " + cls + "\">" + sign + delta.toFixed(1) + "%</span></button>" +
      "<div class=\"gbars\">" +
      "<div class=\"bar-row\"><div class=\"name\">assay (fe)</div>" +
      "<div class=\"bar-track\"><div class=\"bar-fill\" data-width=\"" + (fe / max * 100) + "\"></div></div>" +
      "<div class=\"value\" data-count=\"" + fe + "\">0</div></div>" +
      "<div class=\"bar-row\"><div class=\"name\">best solidity</div>" +
      "<div class=\"bar-track\"><div class=\"bar-fill sol\" data-width=\"" + (sol / max * 100) + "\"></div></div>" +
      "<div class=\"value\" data-count=\"" + sol + "\">0</div></div>" +
      "</div>" +
      "<div class=\"gdetail\"><p>" + (FIXTURE_NOTES[row[0]] || "") + "</p></div>" +
      "</div>"
    );
  }).join("");
  groups.querySelectorAll(".ghead").forEach((head) => {
    head.addEventListener("click", () => {
      const open = head.parentElement.classList.toggle("open");
      head.setAttribute("aria-expanded", open ? "true" : "false");
    });
  });
  observe("#gas-groups", (container) => {
    container.querySelectorAll(".bar-fill").forEach((fill) => {
      fill.style.width = fill.dataset.width + "%";
    });
    container.querySelectorAll(".value[data-count]").forEach((value) => {
      countUp(value, Number(value.dataset.count));
    });
  });
  initCostBox();
}

function formatEth(wei) {
  const eth = wei / 1e18;
  if (eth === 0) return "0 ETH";
  if (eth < 0.000001) return eth.toExponential(2) + " ETH";
  return eth.toFixed(6).replace(/0+$/, "").replace(/\.$/, "") + " ETH";
}

const GAS_PRICE_RPCS = [
  "https://ethereum-rpc.publicnode.com",
  "https://eth.llamarpc.com"
];

async function fetchGasPriceGwei() {
  for (const url of GAS_PRICE_RPCS) {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), 5000);
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_gasPrice", params: [] }),
        signal: abort.signal
      });
      const data = await response.json();
      const wei = Number(data.result);
      if (Number.isFinite(wei) && wei > 0) return wei / 1e9;
    } catch {
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

function initCostBox() {
  const rowsHost = document.getElementById("cost-rows");
  const input = document.getElementById("gwei");
  if (!rowsHost || !input) return;
  const liveTag = document.getElementById("gwei-live");
  function render() {
    const gwei = Math.max(0, Number(input.value) || 0);
    rowsHost.innerHTML = END_TO_END.map((entry) => {
      const wei = entry.gas * gwei * 1e9;
      return (
        "<div class=\"cost-row\"><span class=\"cost-name\">" + entry.name + "</span>" +
        "<span class=\"cost-gas\">" + entry.gas.toLocaleString("en-US") + " gas</span>" +
        "<span class=\"cost-eth\">" + formatEth(wei) + "</span>" +
        "<span class=\"cost-detail\">" + entry.detail + "</span></div>"
      );
    }).join("");
  }
  input.addEventListener("input", () => {
    if (liveTag) liveTag.hidden = true;
    render();
  });
  render();
  fetchGasPriceGwei().then((gwei) => {
    if (gwei === null || document.activeElement === input) return;
    input.value = gwei >= 10 ? gwei.toFixed(1) : gwei.toFixed(3);
    if (liveTag) liveTag.hidden = false;
    render();
  }).catch(() => {});
}

async function loadFindings() {
  const data = await fetch("findings.json", { cache: "no-store" }).then((r) => r.json());
  document.getElementById("findings").innerHTML = data.findings.map((finding) =>
    "<article class=\"finding reveal\"><div class=\"meta\">" +
    "<span class=\"fid\">finding " + String(finding.id).padStart(2, "0") + "</span>" +
    "<span class=\"badge " + finding.severity + "\">" + finding.severity + "</span>" +
    "<span class=\"badge status\">" + finding.status + "</span></div>" +
    "<h3>" + finding.title + "</h3><p>" + finding.body + "</p></article>"
  ).join("");
  observe("#findings .reveal", (target) => target.classList.add("in-view"));
}

async function loadHalo() {
  const response = await fetch("bulk_receipts.json", { cache: "no-store" });
  if (!response.ok) return;
  const data = await response.json();
  const meta = data.meta;
  const receipts = data.receipts;
  if (!meta || !Array.isArray(receipts) || receipts.length === 0) return;
  const svg = document.getElementById("halo");
  const center = 380;
  const total = meta.accounts + meta.slots;
  const parts = [];
  parts.push("<circle class=\"halo-ring-guide\" cx=\"380\" cy=\"380\" r=\"236\"></circle>");
  parts.push("<circle class=\"halo-ring-guide\" cx=\"380\" cy=\"380\" r=\"318\"></circle>");
  receipts.forEach((receipt, index) => {
    const angle = (index / receipts.length) * 2 * Math.PI - Math.PI / 2;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const kind = receipt.contract ? "contract" : "eoa";
    const label = (receipt.contract ? "contract " : "eoa ") + receipt.address +
      (receipt.slots.length ? " · slots " + receipt.slots.map((s) => Number(s.slot) + (s.present ? "" : " (absent)")).join(", ") : "");
    parts.push(
      "<line class=\"halo-tick " + kind + "\" stroke-width=\"1.6\"" +
      " x1=\"" + (center + cos * 218).toFixed(1) + "\" y1=\"" + (center + sin * 218).toFixed(1) + "\"" +
      " x2=\"" + (center + cos * 254).toFixed(1) + "\" y2=\"" + (center + sin * 254).toFixed(1) + "\"" +
      " data-label=\"" + label + "\"></line>"
    );
  });
  const slotTicks = [];
  receipts.forEach((receipt) => {
    receipt.slots.forEach((slot) => {
      slotTicks.push({
        present: slot.present,
        label: "slot " + Number(slot.slot) + (slot.present ? " proven present" : " proven absent") + " · " + receipt.address
      });
    });
  });
  slotTicks.forEach((tick, index) => {
    const angle = (index / slotTicks.length) * 2 * Math.PI - Math.PI / 2;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    parts.push(
      "<line class=\"halo-tick " + (tick.present ? "slot-present" : "slot-absent") + "\" stroke-width=\"1.6\"" +
      " x1=\"" + (center + cos * 300).toFixed(1) + "\" y1=\"" + (center + sin * 300).toFixed(1) + "\"" +
      " x2=\"" + (center + cos * 336).toFixed(1) + "\" y2=\"" + (center + sin * 336).toFixed(1) + "\"" +
      " data-label=\"" + tick.label + "\"></line>"
    );
  });
  svg.innerHTML = parts.join("");
  const detail = document.getElementById("halo-detail");
  svg.addEventListener("mouseover", (event) => {
    const label = event.target.dataset && event.target.dataset.label;
    if (label) detail.textContent = label;
  });
  document.getElementById("halo-lede").textContent =
    "One run of tools/bulk_verify.py: " + meta.accounts.toLocaleString("en-US") +
    " real mainnet accounts harvested from the transactions of " +
    (meta.blockRange[1] - meta.blockRange[0] + 1) + " blocks, plus " +
    meta.slots.toLocaleString("en-US") +
    " storage slots on the contracts among them, every one verified by the native CLI from beacon root " +
    meta.beaconRoot.slice(0, 18) + "… alone. Each tick is one receipt.";
  document.getElementById("halo-meta").textContent =
    "beacon slot " + meta.beaconSlot.toLocaleString("en-US") +
    " · execution block " + meta.executionBlock.toLocaleString("en-US") +
    " · " + meta.when + " · rerun: " + meta.reproduce;
  document.getElementById("scale").hidden = false;
  observe("#halo-count", (element) => countUp(element, total));
}

loadHalo().catch(() => {});

loadStats().catch(() => {});
loadGas().catch(() => {});
loadFindings().catch(() => {});
