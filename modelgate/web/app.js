"use strict";
// All untrusted strings (repo code, file names, LLM output) are inserted with textContent only.

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const HOT = new Set(["socket.connect", "net.connect", "subprocess.Popen", "process.execve", "os.system",
  "env.read", "os.memfd_create", "memfd_create", "prctl.set_name", "canary.exfil", "file.open", "open"]);

async function loadFixtures() {
  try {
    const r = await fetch("/api/fixtures");
    const data = await r.json();
    const box = $("fixtures");
    for (const f of data.fixtures) {
      const b = el("button", "chip", f);
      b.type = "button";
      b.addEventListener("click", () => { $("repo").value = "fixtures/" + f; $("revision").value = ""; runScan(); });
      box.appendChild(b);
    }
  } catch (_) { /* optional */ }
}

function setStatus(text, isError) {
  const s = $("status");
  s.textContent = text;
  s.classList.toggle("hidden", !text);
  s.classList.toggle("error", !!isError);
}

async function runScan() {
  const repo = $("repo").value.trim();
  if (!repo) return;
  const rev = $("revision").value.trim();
  const params = new URLSearchParams({ repo });
  if (rev) params.set("revision", rev);
  $("go").disabled = true;
  $("result").classList.add("hidden");
  setStatus("Scanning: fetch pinned code, static AST, sandbox (Docker + strace), policy, explanation…");
  try {
    const r = await fetch("/api/scan?" + params.toString());
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || ("HTTP " + r.status));
    render(data);
    setStatus("");
  } catch (e) {
    setStatus("Scan failed: " + e.message, true);
  } finally {
    $("go").disabled = false;
  }
}

function render(rep) {
  $("result").classList.remove("hidden");
  const banner = $("banner");
  banner.className = "banner v-" + rep.verdict.toLowerCase();
  $("verdict").textContent = rep.verdict;
  const pin = rep.sha ? "sha " + rep.sha.slice(0, 12) : "local dir";
  $("meta").textContent = `${rep.target}  ·  ${pin}  ·  code ${String(rep.code_hash || "").slice(0, 12)}  ·  ${rep.scan_seconds}s` +
    (rep.allowlisted ? "  ·  allowlisted" : "");

  const sb = rep.sandbox || {};
  const iso = $("isolation");
  if (sb.mode === "none" || sb.mode === "subprocess") {
    iso.textContent = "NOT ISOLATED: " + (sb.note || "");
    iso.classList.remove("hidden");
  } else {
    iso.classList.add("hidden");
  }

  renderFindings(rep.findings || []);
  renderRefs(rep.references || []);
  renderTimeline(sb);
  renderExplanation(rep.explanation);
}

function renderFindings(findings) {
  const box = $("findings");
  clear(box);
  const shown = findings.filter((f) => f.severity !== "low")
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  $("findings-count").textContent = String(shown.length);
  if (!shown.length) { box.appendChild(el("p", "empty", "No findings.")); return; }
  for (const f of shown) {
    const card = el("div", "finding sev-" + f.severity);
    const head = el("div", "fhead");
    head.appendChild(el("span", "sev", f.severity.toUpperCase()));
    head.appendChild(el("span", "rule", f.rule_id));
    head.appendChild(el("span", "loc", f.line ? `${f.file}:${f.line}` : f.file));
    head.appendChild(el("span", "src", f.source));
    card.appendChild(head);
    card.appendChild(el("div", "msg", f.message));
    if (f.snippet) {
      const pre = el("pre", "code");
      if (f.line) pre.appendChild(el("span", "ln", String(f.line).padStart(4, " ") + " │ "));
      pre.appendChild(el("span", "hl", f.snippet));
      card.appendChild(pre);
    }
    box.appendChild(card);
  }
}

function renderRefs(refs) {
  $("refs-wrap").classList.toggle("hidden", !refs.length);
  const box = $("refs");
  clear(box);
  for (const r of refs) {
    const row = el("div", "ref v-" + String(r.verdict).toLowerCase());
    row.appendChild(el("span", "refv", r.verdict));
    row.appendChild(el("span", "refn", r.target));
    row.appendChild(el("span", "refsha", r.sha ? r.sha.slice(0, 12) : "-"));
    row.appendChild(el("div", "refwhy", (r.reasons || []).join("; ")));
    box.appendChild(row);
  }
}

function renderTimeline(sb) {
  const box = $("timeline");
  clear(box);
  $("sandbox-mode").textContent = `${sb.mode || "?"}${sb.strace ? " + strace" : ""} · ${sb.status || "?"}`;
  const evs = (sb.events || []).filter((e) => e.event !== "module.imported");
  if (!evs.length) { box.appendChild(el("li", "empty", sb.note || "No events.")); return; }
  for (const e of evs.slice(0, 80)) {
    const li = el("li", HOT.has(e.event) ? "ev hot" : "ev");
    li.appendChild(el("span", "t", Number(e.t || 0).toFixed(3) + "s"));
    li.appendChild(el("span", "esrc", e.source || "audit"));
    if (e.phase) li.appendChild(el("span", "phase", e.phase));
    li.appendChild(el("span", "ename", e.event));
    if (e.file) li.appendChild(el("span", "loc", `${e.file}:${e.line}`));
    li.appendChild(el("div", "detail", e.detail));
    box.appendChild(li);
  }
}

function renderExplanation(x) {
  const box = $("explanation");
  clear(box);
  if (!x) { box.appendChild(el("p", "empty", "No explanation.")); return; }
  box.appendChild(el("p", "summary", x.summary));
  if (x.findings && x.findings.length) {
    const ul = el("ul");
    for (const f of x.findings) {
      const li = el("li");
      li.appendChild(el("span", "loc", `${f.file}:${f.line} [${f.rule_id}] `));
      li.appendChild(el("span", "", f.explanation));
      ul.appendChild(li);
    }
    box.appendChild(ul);
  }
  if (x.attack_techniques && x.attack_techniques.length) {
    box.appendChild(el("p", "mitre", "MITRE ATT&CK: " + x.attack_techniques.join(", ")));
  }
  if (x.recommended_action) box.appendChild(el("p", "action", "Recommended: " + x.recommended_action));
  box.appendChild(el("p", "source", "source: " + (x.source || "?") + " · label: " + (x.label || "advisory")));
}

$("scan-form").addEventListener("submit", (ev) => { ev.preventDefault(); runScan(); });
loadFixtures();
