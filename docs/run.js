const RPC = "https://ethereum-rpc.publicnode.com";
const WINDOW_SECONDS = 8191 * 12;

const state = { data: null, busy: false };

async function rpc(method, params) {
  const reply = await fetch(RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  const answer = await reply.json();
  if (answer.error) throw answer.error;
  return answer.result;
}

function ageOf(entry) {
  return Math.floor(Date.now() / 1000) - entry.timestampKey;
}

function hoursLeft(entry) {
  return (WINDOW_SECONDS - ageOf(entry)) / 3600;
}

function short(hex) {
  return hex.slice(0, 6) + "…" + hex.slice(-4);
}

function decodeWord(word, kind) {
  if (!/^[0-9a-f]{64}$/.test(word)) return "invalid word";
  if (kind === "uint256" || kind === "uint64") {
    const value = BigInt("0x" + word);
    return value.toLocaleString("en-US");
  }
  if (kind === "bool") return BigInt("0x" + word) === 1n ? "yes" : "no";
  if (kind === "address") return "0x" + word.slice(24);
  return "0x" + word;
}

function ring(entry) {
  const used = Math.min(ageOf(entry) / WINDOW_SECONDS, 1);
  const radius = 8;
  const circumference = 2 * Math.PI * radius;
  const left = hoursLeft(entry);
  const cls = left < 6 ? "agering old" : "agering";
  const hours = Math.max(ageOf(entry) / 3600, 0).toFixed(1);
  return `<span class="${cls}" title="the 4788 ring holds this anchor ${left.toFixed(1)} more hours">
    <svg width="20" height="20" viewBox="0 0 20 20">
      <circle class="track" cx="10" cy="10" r="${radius}" fill="none" stroke-width="2.5"></circle>
      <circle class="arc" cx="10" cy="10" r="${radius}" fill="none" stroke-width="2.5"
        stroke-dasharray="${(circumference * (1 - used)).toFixed(2)} ${circumference.toFixed(2)}"></circle>
    </svg>
    anchor ${hours}h old</span>`;
}

function render() {
  const { contract, entries } = state.data;
  const link = document.getElementById("contract-link");
  link.textContent = short(contract);
  link.href = "https://etherscan.io/address/" + contract;

  const live = entries.filter((entry) => hoursLeft(entry) > 0.5);
  const freshest = Math.min(...live.map(ageOf));
  const freshline = document.getElementById("freshness");
  if (live.length) {
    freshline.textContent =
      live.length + " proofs armed · freshest anchor " + (freshest / 3600).toFixed(1) +
      "h old · chain cards refresh every 6h, state cards daily";
  } else {
    freshline.textContent = "the pipeline has not refreshed recently; buttons are disarmed rather than dishonest";
    freshline.parentElement.classList.add("stale");
  }

  const cards = document.getElementById("cards");
  cards.innerHTML = entries
    .map((entry) => {
      const bytes = (entry.calldata.length - 2) / 2;
      const dead = hoursLeft(entry) <= 0.5;
      return `<article class="card" id="card-${entry.id}">
        <span class="proofsize">${bytes.toLocaleString("en-US")} bytes of proof</span>
        <h3>${entry.title}</h3>
        <p>${entry.story}</p>
        <div class="card-meta">
          ${ring(entry)}
          <button class="runbtn" data-id="${entry.id}" ${dead ? "disabled" : ""}>
            ${dead ? "anchor expired" : "Run on Ethereum"}
          </button>
        </div>
      </article>`;
    })
    .join("");

  cards.querySelectorAll(".runbtn").forEach((button) => {
    button.addEventListener("click", () => run(button.dataset.id));
  });
}

function step(name, status, note) {
  const row = document.querySelector(`.rail-steps li[data-step="${name}"]`);
  row.classList.toggle("on", status !== "off");
  row.classList.toggle("done", status === "done");
  if (note !== undefined) document.getElementById("note-" + name).textContent = note;
}

function resetRail(title) {
  document.getElementById("rail").hidden = false;
  document.getElementById("rail-name").textContent = title;
  ["build", "send", "verify", "answer"].forEach((name) => step(name, "off", ""));
  document.getElementById("result").hidden = true;
  document.getElementById("failure").hidden = true;
  document.getElementById("raw-call").hidden = true;
}

async function run(id) {
  if (state.busy) return;
  state.busy = true;
  try {
  const entry = state.data.entries.find((candidate) => candidate.id === id);
  document.querySelectorAll(".card").forEach((card) => card.classList.remove("running", "proven"));
  const card = document.getElementById("card-" + id);
  card.classList.add("running");
  resetRail(entry.title);
  document.getElementById("rail").scrollIntoView({ behavior: "smooth", block: "nearest" });

  const bytes = (entry.calldata.length - 2) / 2;
  step("build", "done", bytes.toLocaleString("en-US") + " bytes");
  step("send", "on");

  const started = performance.now();
  try {
    const call = { to: state.data.contract, data: entry.calldata };
    const [answer, gas] = await Promise.all([
      rpc("eth_call", [call, "latest"]),
      rpc("eth_estimateGas", [call]).catch(() => null)
    ]);
    const elapsed = Math.round(performance.now() - started);
    step("send", "done", elapsed + " ms");
    step("verify", "done", "every hash checked in the EVM");
    step("answer", "done", (answer.length - 2) / 2 + " bytes back");

    const rows = document.getElementById("result-rows");
    const body = answer.slice(2);
    rows.innerHTML = entry.returns
      .map((ret, index) => {
        const word = body.slice(index * 64, index * 64 + 64);
        const value = decodeWord(word, ret.type);
        const big = index === 0 ? ' class="big"' : "";
        return `<dt>${ret.label}</dt><dd${big}>${value}</dd>`;
      })
      .join("");

    const badge = document.getElementById("gas-badge");
    badge.textContent = gas
      ? "~" + parseInt(gas, 16).toLocaleString("en-US") + " gas of verification"
      : "gas estimate unavailable";

    const raw = document.getElementById("raw-call");
    raw.textContent =
      "eth_call to " + state.data.contract + "\n\ncalldata (" + bytes + " bytes):\n" + entry.calldata +
      "\n\nreturned:\n" + answer;

    document.getElementById("result").hidden = false;
    card.classList.remove("running");
    card.classList.add("proven");
  } catch (error) {
    step("send", "done");
    step("verify", "on", "");
    const failure = document.getElementById("failure");
    failure.hidden = false;
    const text = error.message || JSON.stringify(error);
    failure.textContent = text.includes("fetch")
      ? "The RPC endpoint could not be reached. Nothing was verified either way; try again in a moment."
      : "The contract refused this call: " + text +
        ". If the anchor ring shows the proof is old, the 4788 window has closed and the next pipeline run re-arms it.";
    card.classList.remove("running");
  }
  } finally {
    state.busy = false;
  }
}

document.getElementById("raw-toggle").addEventListener("click", () => {
  const raw = document.getElementById("raw-call");
  raw.hidden = !raw.hidden;
});

fetch("run.json", { cache: "no-store" })
  .then((reply) => reply.json())
  .then((data) => {
    state.data = data;
    render();
    setInterval(() => { if (!state.busy) render(); }, 60000);
  })
  .catch(() => {
    document.getElementById("freshness").textContent = "run.json failed to load";
  });

const BEACON = "https://ethereum-beacon-api.publicnode.com";

function abiWord(value) {
  if (typeof value === "bigint" || typeof value === "number") {
    return BigInt(value).toString(16).padStart(64, "0");
  }
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  return clean.padStart(64, "0");
}

function abiBytes(hexData) {
  const clean = hexData.startsWith("0x") ? hexData.slice(2) : hexData;
  const length = clean.length / 2;
  const padded = clean + "0".repeat((64 - (clean.length % 64)) % 64);
  return abiWord(length) + padded;
}

function abiBytesArray(items) {
  let heads = "";
  let tail = "";
  for (const item of items) {
    heads += abiWord(32 * items.length + tail.length / 2);
    tail += abiBytes(item);
  }
  return abiWord(items.length) + heads + tail;
}

function abiWords(items) {
  return abiWord(items.length) + items.map(abiWord).join("");
}

function proveStorageCalldata(anchor, proof, slot) {
  const selector = "12486b8d";
  const parts = [
    abiWord(anchor.timestamp),
    abiWord(anchor.header.slot),
    abiWord(anchor.header.proposer_index),
    abiWord(anchor.header.parent_root),
    abiWord(anchor.header.state_root),
    abiWord(anchor.header.body_root),
    abiWord(anchor.stateRoot),
    "dyn",
    abiWord(proof.address),
    "dyn",
    abiWord(slot),
    "dyn",
  ];
  const dynamics = [
    abiWords(anchor.branch),
    abiBytesArray(proof.accountProof),
    abiBytesArray(proof.storageProof[0].proof),
  ];
  const headBytes = 32 * parts.length;
  let heads = "";
  let tail = "";
  let next = 0;
  for (const part of parts) {
    if (part === "dyn") {
      heads += abiWord(headBytes + tail.length / 2);
      tail += dynamics[next];
      next += 1;
    } else {
      heads += part;
    }
  }
  return "0x" + selector + heads + tail;
}

function ystep(name, status, note) {
  const row = document.querySelector(`#y-steps li[data-ystep="${name}"]`);
  row.classList.toggle("on", status !== "off");
  row.classList.toggle("done", status === "done");
  if (note !== undefined) document.getElementById("ynote-" + name).textContent = note;
}

document.getElementById("yours-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.busy) return;
  state.busy = true;
  const address = document.getElementById("y-address").value.trim().toLowerCase();
  const slotText = document.getElementById("y-slot").value.trim();
  const steps = document.getElementById("y-steps");
  steps.hidden = false;
  ["anchor", "selfcheck", "proof", "call"].forEach((name) => ystep(name, "off", ""));
  document.getElementById("y-result").hidden = true;
  document.getElementById("y-failure").hidden = true;
  const failure = document.getElementById("y-failure");

  try {
    const slot = BigInt(slotText);
    if (slot < 0n) throw new Error("the storage slot must not be negative");
    ystep("anchor", "on");
    const started = performance.now();
    const anchor = await ANCHOR.build(BEACON);
    ystep("anchor", "done", "slot " + anchor.anchorSlot + " · " + Math.round(performance.now() - started) + " ms");
    ystep("selfcheck", "done", anchor.blockRoot.slice(0, 14) + "…");

    ystep("proof", "on");
    const proof = await rpc("eth_getProof", [
      address,
      ["0x" + slot.toString(16)],
      "0x" + anchor.blockNumber.toString(16)
    ]);
    const nodes = proof.accountProof.length + proof.storageProof[0].proof.length;
    ystep("proof", "done", nodes + " trie nodes");

    ystep("call", "on");
    const data = proveStorageCalldata(anchor, proof, slot);
    const answer = await rpc("eth_call", [{ to: state.data.contract, data }, "latest"]);
    ystep("call", "done", (data.length - 2) / 2 + " bytes sent");

    const value = BigInt("0x" + answer.slice(2, 66));
    const provenSlot = BigInt("0x" + answer.slice(66, 130));
    document.getElementById("y-rows").innerHTML =
      "<dt>address</dt><dd>" + address + "</dd>" +
      "<dt>slot</dt><dd>" + slotText + "</dd>" +
      "<dt>value</dt><dd class=\"big\">0x" + value.toString(16).padStart(64, "0") + "</dd>" +
      "<dt>beacon slot</dt><dd>" + provenSlot.toLocaleString("en-US") + "</dd>";
    document.getElementById("y-result").hidden = false;
  } catch (error) {
    failure.hidden = false;
    failure.textContent = "Refused: " + (error.message || JSON.stringify(error));
  } finally {
    state.busy = false;
  }
});

const GENESIS_TIME = 1606824023;

function proveReceiptCalldata(anchor, nodes, txIndex) {
  const parts = [
    abiWord(anchor.timestamp),
    abiWord(anchor.header.slot),
    abiWord(anchor.header.proposer_index),
    abiWord(anchor.header.parent_root),
    abiWord(anchor.header.state_root),
    abiWord(anchor.header.body_root),
    abiWord(anchor.receiptsRoot),
    "dyn",
    abiWord(txIndex),
    "dyn",
  ];
  const dynamics = [abiWords(anchor.receiptsBranch), abiBytesArray(nodes)];
  const headBytes = 32 * parts.length;
  let heads = "";
  let tail = "";
  let next = 0;
  for (const part of parts) {
    if (part === "dyn") {
      heads += abiWord(headBytes + tail.length / 2);
      tail += dynamics[next];
      next += 1;
    } else {
      heads += part;
    }
  }
  return "0x2acbb5df" + heads + tail;
}

document.getElementById("tx-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.busy) return;
  state.busy = true;
  const txHash = document.getElementById("t-hash").value.trim().toLowerCase();
  const steps = document.getElementById("t-steps");
  steps.hidden = false;
  ["find", "anchor", "trie", "call"].forEach((name) => tstep(name, "off", ""));
  document.getElementById("t-result").hidden = true;
  document.getElementById("t-failure").hidden = true;
  const failure = document.getElementById("t-failure");

  try {
    tstep("find", "on");
    const receipt = await rpc("eth_getTransactionReceipt", [txHash]);
    if (!receipt) throw new Error("no receipt found for that hash");
    const block = await rpc("eth_getBlockByNumber", [receipt.blockNumber, false]);
    const slot = (parseInt(block.timestamp, 16) - GENESIS_TIME) / 12;
    const age = Math.floor(Date.now() / 1000) - parseInt(block.timestamp, 16);
    if (age > 26 * 3600) {
      throw new Error("that transaction is " + (age / 3600).toFixed(1) +
        "h old; the 4788 ring only reaches about 27h back, so pick a newer one");
    }
    tstep("find", "done", "block " + parseInt(receipt.blockNumber, 16) + " · slot " + slot);

    tstep("anchor", "on");
    const anchor = await ANCHOR.build(BEACON, null, { slot });
    if (anchor.blockHash.toLowerCase() !== block.hash.toLowerCase()) {
      throw new Error("the beacon block's payload is not this execution block");
    }
    tstep("anchor", "done", anchor.blockRoot.slice(0, 14) + "…");

    tstep("trie", "on");
    const receipts = await rpc("eth_getBlockReceipts", [receipt.blockNumber]);
    const trie = RECEIPTS.buildTrie(receipts, block.receiptsRoot);
    const txIndex = parseInt(receipt.transactionIndex, 16);
    const nodes = RECEIPTS.prove(trie, txIndex).map(RECEIPTS.toHex);
    tstep("trie", "done", receipts.length + " receipts rebuilt, root matches the header");

    tstep("call", "on");
    const data = proveReceiptCalldata(anchor, nodes, txIndex);
    const answer = await rpc("eth_call", [{ to: state.data.contract, data }, "latest"]);
    tstep("call", "done", (data.length - 2) / 2 + " bytes sent");

    const word = (index) => answer.slice(2 + 64 * index, 66 + 64 * index);
    document.getElementById("t-rows").innerHTML =
      "<dt>transaction</dt><dd>" + txHash + "</dd>" +
      "<dt>succeeded</dt><dd class=\"big\">" + (BigInt("0x" + word(0)) === 1n ? "yes" : "no") + "</dd>" +
      "<dt>cumulative gas</dt><dd>" + BigInt("0x" + word(1)).toLocaleString("en-US") + "</dd>" +
      "<dt>tx type</dt><dd>" + BigInt("0x" + word(2)) + "</dd>" +
      "<dt>log count</dt><dd>" + BigInt("0x" + word(3)) + "</dd>" +
      "<dt>beacon slot</dt><dd>" + BigInt("0x" + word(4)).toLocaleString("en-US") + "</dd>";
    document.getElementById("t-result").hidden = false;
  } catch (error) {
    failure.hidden = false;
    failure.textContent = "Refused: " + (error.message || JSON.stringify(error));
  } finally {
    state.busy = false;
  }
});

function tstep(name, status, note) {
  const row = document.querySelector(`#t-steps li[data-tstep="${name}"]`);
  row.classList.toggle("on", status !== "off");
  row.classList.toggle("done", status === "done");
  if (note !== undefined) document.getElementById("tnote-" + name).textContent = note;
}
