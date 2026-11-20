const DOCUMENTS = [
  { file: "deployment.md", title: "Mainnet deployment" },
  { file: "gas.md", title: "Gas benchmarks" },
  { file: "consuming.md", title: "Use Assay in your contract" },
  { file: "live_log.md", title: "Live verification log" },
  { file: "audit.md", title: "Audit and findings" },
  { file: "../README.md", title: "README" }
];

const list = document.getElementById("docs-list");
const body = document.getElementById("doc-body");

async function available() {
  const found = [];
  for (const entry of DOCUMENTS) {
    try {
      const response = await fetch(entry.file, { method: "HEAD", cache: "no-store" });
      if (response.ok) found.push(entry);
    } catch {
    }
  }
  return found;
}

async function show(entry, link) {
  list.querySelectorAll("a").forEach((other) => other.classList.remove("here"));
  link.classList.add("here");
  body.innerHTML = "<p class=\"docs-loading\">loading…</p>";
  try {
    const text = await fetch(entry.file, { cache: "no-store" }).then((r) => {
      if (!r.ok) throw new Error(String(r.status));
      return r.text();
    });
    body.innerHTML = marked.parse(text, { mangle: false, headerIds: false });
  } catch {
    body.innerHTML = "<p class=\"docs-loading\">could not load " + entry.file + "</p>";
  }
}

available().then((entries) => {
  if (entries.length === 0) {
    body.innerHTML = "<p class=\"docs-loading\">no documents found</p>";
    return;
  }
  list.innerHTML = "";
  entries.forEach((entry, index) => {
    const link = document.createElement("a");
    link.textContent = entry.title;
    link.href = "#" + entry.file.replace(/[^a-z0-9_.-]/gi, "");
    link.addEventListener("click", (event) => {
      event.preventDefault();
      history.replaceState(null, "", link.getAttribute("href"));
      show(entry, link);
    });
    list.appendChild(link);
    if (index === 0) show(entry, link);
  });
  const wanted = location.hash.slice(1);
  if (wanted) {
    const match = entries.findIndex((entry) => entry.file.replace(/[^a-z0-9_.-]/gi, "") === wanted);
    if (match > 0) show(entries[match], list.children[match]);
  }
}).catch(() => {
  body.innerHTML = "<p class=\"docs-loading\">could not list documents</p>";
});
