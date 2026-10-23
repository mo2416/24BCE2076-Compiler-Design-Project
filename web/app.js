// Frontend for the taint analyzer. Talks to server.py over POST /api/analyze.
// When the page is served by server.py itself, it uses the same origin.
// When it is opened from the hosted copy, it calls http://127.0.0.1:8000.

const VULNERABLE_EXAMPLE = `#include <stdlib.h>

int main(void) {
    char *cmd = getenv("USER_CMD");   /* untrusted input */
    char *run = cmd;                  /* copied */
    system(run);                      /* reaches the sink */
    return 0;
}
`;

const SAFE_EXAMPLE = `#include <stdlib.h>

int main(int argc, char **argv) {
    char *cmd = getenv("USER_CMD");   /* read, but not used for the command */
    if (argc > 1) {
        cmd = "ls -l";
    } else {
        cmd = "date";
    }
    system(cmd);                      /* only constants reach the sink */
    return 0;
}
`;

const $ = (id) => document.getElementById(id);
const codeEl = $("code");
const resultEl = $("result");
const analyzeBtn = $("analyze");
const backendEl = $("backend-url");

const sameOrigin = ["127.0.0.1", "localhost"].includes(location.hostname) && location.port !== "";
const DEFAULT_BACKEND = sameOrigin ? location.origin : "http://127.0.0.1:8000";

function loadBackend() {
  let saved = null;
  try { saved = localStorage.getItem("backend-url"); } catch (e) { /* storage blocked */ }
  backendEl.value = saved || DEFAULT_BACKEND;
}

function saveBackend() {
  try { localStorage.setItem("backend-url", backendEl.value.trim()); } catch (e) { /* ignore */ }
}

function apiUrl(path) {
  return backendEl.value.trim().replace(/\/+$/, "") + path;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function lineText(line) {
  return line === null || line === undefined || line === 0 ? "line unknown" : `line ${line}`;
}

function setBackendStatus(state, text) {
  $("backend-status").className = "dot " + state;
  $("backend-text").textContent = text;
}

async function checkBackend() {
  try {
    const res = await fetch(apiUrl("/api/health"), { cache: "no-store" });
    if (!res.ok) throw new Error(res.status);
    setBackendStatus("up", "connected");
  } catch (e) {
    setBackendStatus("down", "not reachable. Start it with: python3 server.py");
  }
}

function showError(message, stage) {
  resultEl.className = "result error";
  resultEl.innerHTML =
    `<p class="status">Analysis error</p>` +
    (stage ? `<p class="muted">Stage: ${escapeHtml(stage)}</p>` : "") +
    `<pre class="err">${escapeHtml(message)}</pre>` +
    `<p class="muted">An error is not a clean result. Nothing was concluded about this code.</p>`;
}

function renderFinding(f) {
  const flow = f.path.map((step) =>
    `<span class="step ${escapeHtml(step.kind)}" title="${escapeHtml(lineText(step.line))}">${escapeHtml(step.label)}</span>`
  ).join(`<span class="arrow">&rarr;</span>`);

  return `<div class="finding-block">
    <dl>
      <dt>Type</dt><dd><b>${escapeHtml(f.cwe)}</b>: ${escapeHtml(f.title)} (OS command injection)</dd>
      <dt>Function</dt><dd><code>${escapeHtml(f.function)}()</code></dd>
      <dt>Source</dt><dd><code>${escapeHtml(f.source.call)}</code> return value, ${lineText(f.source.line)}</dd>
      <dt>Sink</dt><dd><code>${escapeHtml(f.sink.call)}</code> argument ${f.sink.arg}, ${lineText(f.sink.line)}</dd>
    </dl>
    <div class="flow">${flow}</div>
  </div>`;
}

function showResult(data) {
  if (!data || data.status === "error") {
    showError((data && data.error) || "unknown error", data && data.stage);
    return;
  }
  const stats = data.stats || {};
  const statsLine = `<p class="muted">Analyzed ${stats.functions ?? "?"} function(s): ` +
    `${stats.sources ?? "?"} getenv() call(s), ${stats.sinks ?? "?"} system() call(s).</p>`;

  if (data.status === "finding") {
    resultEl.className = "result finding";
    resultEl.innerHTML =
      `<p class="status">Potential finding: ${data.findings.length} tainted flow(s)</p>` +
      statsLine +
      data.findings.map(renderFinding).join("") +
      `<p class="muted">Untrusted data from getenv() can reach system() under this prototype's rules.</p>`;
  } else if (data.status === "clean") {
    resultEl.className = "result clean";
    resultEl.innerHTML =
      `<p class="status">No tainted flow detected under this prototype's rules</p>` +
      statsLine +
      `<p class="muted">This does not mean the code is safe or secure.</p>`;
  } else {
    showError("unexpected response: " + JSON.stringify(data));
  }
}

async function analyze() {
  const source = codeEl.value;
  if (!source.trim()) {
    showError("Paste some C code first.");
    return;
  }
  saveBackend();
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Analyzing...";
  resultEl.className = "result idle";
  resultEl.innerHTML = `<p class="muted">Compiling to LLVM IR and running the analyzer...</p>`;
  try {
    const res = await fetch(apiUrl("/api/analyze"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source }),
    });
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error(`backend returned HTTP ${res.status} without JSON`);
    }
    showResult(data);
    setBackendStatus("up", "connected");
  } catch (e) {
    setBackendStatus("down", "not reachable");
    showError(
      `Could not reach the backend at ${backendEl.value}.\n` +
      `Start it on your machine with:  python3 server.py\n` +
      `(${e.message})`,
      "network"
    );
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analyze";
  }
}

$("analyze").addEventListener("click", analyze);
$("load-vuln").addEventListener("click", () => { codeEl.value = VULNERABLE_EXAMPLE; });
$("load-safe").addEventListener("click", () => { codeEl.value = SAFE_EXAMPLE; });
$("clear").addEventListener("click", () => {
  codeEl.value = "";
  resultEl.className = "result idle";
  resultEl.innerHTML = `<p class="muted">No analysis yet. Press <b>Analyze</b> to run the analyzer on the code.</p>`;
});
backendEl.addEventListener("change", () => { saveBackend(); checkBackend(); });
codeEl.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze();
});

codeEl.value = VULNERABLE_EXAMPLE;
loadBackend();
checkBackend();
