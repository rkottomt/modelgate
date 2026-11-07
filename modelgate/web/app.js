"use strict";
// Every string that comes from a scanned repo, a file name or the LLM is inserted with textContent only.

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function show(id, on) { $(id).classList.toggle("hidden", !on); }

const SEV = ["critical", "high", "medium", "low"];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const SOURCE_LABEL = { static: "found in code", sandbox: "seen when run", manifest: "repo contents", reference: "linked repo" };
const EVENT_LABEL = {
  "socket.connect": "Opened a network connection", "net.connect": "Opened a network connection",
  "subprocess.Popen": "Started a process", "process.execve": "Started a process", "os.system": "Ran a shell command",
  "open": "Opened a file", "file.open": "Opened a file", "env.read": "Read a secret environment variable",
  "os.memfd_create": "Made an in-memory file", "memfd_create": "Made an in-memory file",
  "prctl.set_name": "Renamed its process", "canary.exfil": "Sent a planted secret out", "exec": "Ran generated code",
  "compile": "Built code at runtime", "sandbox.start": "Sandbox started", "sandbox.end": "Sandbox finished",
};
const HOT = new Set(["socket.connect", "net.connect", "subprocess.Popen", "process.execve", "os.system", "env.read",
  "os.memfd_create", "memfd_create", "prctl.set_name", "canary.exfil", "file.open", "open", "exec"]);

const state = { token: null, report: null, filters: new Set(["critical", "high", "medium"]), allEvents: false, timer: null };

/* ---------- small helpers ---------- */

function copyButton(text, label) {
  const b = el("button", "copy", label || "Copy");
  b.type = "button";
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); b.textContent = "Copied"; }
    catch (_) { b.textContent = "Select and copy manually"; }
    setTimeout(() => { b.textContent = label || "Copy"; }, 1400);
  });
  return b;
}

function snippet(code) {
  const wrap = el("div", "snippet");
  wrap.appendChild(el("pre", "", code));
  wrap.appendChild(copyButton(code));
  return wrap;
}

function ago(ts) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  return Math.round(s / 3600) + " h ago";
}

function hfLink(rep, file, line) {
  if (rep.is_fixture || !rep.sha || !file || file.startsWith("(")) return null;
  const parts = rep.target.split("/").map(encodeURIComponent).join("/");
  const path = file.split("/").map(encodeURIComponent).join("/");
  return `https://huggingface.co/${parts}/blob/${rep.sha}/${path}` + (line ? `#L${line}` : "");
}

function startTimer(node, prefix) {
  stopTimer();
  const t0 = performance.now();
  const tick = () => { node.textContent = prefix + ((performance.now() - t0) / 1000).toFixed(1) + "s"; };
  tick();
  state.timer = setInterval(tick, 100);
}
function stopTimer() { if (state.timer) clearInterval(state.timer); state.timer = null; }

/* ---------- side rail ---------- */

async function loadFixtures() {
  try {
    const data = await (await fetch("/api/fixtures")).json();
    const box = $("fixtures");
    clear(box);
    for (const f of data.fixtures) {
      const li = el("li");
      const b = el("button");
      b.type = "button";
      b.appendChild(el("span", "name", f.replace(/_/g, " ")));
      b.title = "Scan fixtures/" + f;
      b.addEventListener("click", () => { $("repo").value = "fixtures/" + f; $("revision").value = ""; runScan(); });
      li.appendChild(b);
      box.appendChild(li);
    }
  } catch (_) { /* examples are optional */ }
}

async function loadHistory() {
  try {
    const data = await (await fetch("/api/history")).json();
    const box = $("history");
    clear(box);
    if (!data.scans.length) { box.appendChild(el("li", "muted", "None yet")); return; }
    const seen = new Set();
    for (const s of data.scans) {
      const k = s.target + "@" + (s.revision || "");
      if (seen.has(k) || seen.size >= 15) continue;
      seen.add(k);
      const li = el("li");
      const b = el("button");
      b.type = "button";
      b.title = `${s.target}${s.revision ? "@" + s.revision : ""}: ${s.verdict}, ${ago(s.scanned_at)}`;
      b.appendChild(el("span", "dot v-" + String(s.verdict).toLowerCase()));
      b.appendChild(el("span", "name", s.target.replace(/^fixtures\//, "")));
      b.addEventListener("click", () => openReport(s.token));
      li.appendChild(b);
      box.appendChild(li);
    }
  } catch (_) { /* ignore */ }
}

/* ---------- scanning ---------- */

function setUrl(repo, rev) {
  const p = new URLSearchParams();
  if (repo) p.set("repo", repo);
  if (rev) p.set("rev", rev);
  history.replaceState(null, "", p.toString() ? "?" + p.toString() : "/");
}

async function runScan() {
  const repo = $("repo").value.trim();
  if (!repo) { $("repo").focus(); return; }
  const rev = $("revision").value.trim();
  setUrl(repo, rev);
  const params = new URLSearchParams({ repo });
  if (rev) params.set("revision", rev);

  $("go").disabled = true;
  show("intro", false); show("result", false); show("error", false); show("progress", true);
  $("progress-text").textContent = "Scanning " + repo;
  startTimer($("progress-time"), "");
  try {
    const r = await fetch("/api/scan?" + params.toString());
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || ("The server returned HTTP " + r.status));
    render(data);
    loadHistory();
  } catch (e) {
    $("error").textContent = "Couldn't scan " + repo + ". " + e.message;
    show("error", true);
  } finally {
    stopTimer();
    show("progress", false);
    $("go").disabled = false;
  }
}

async function openReport(token) {
  try {
    const r = await fetch("/api/report?token=" + encodeURIComponent(token));
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "not found");
    $("repo").value = data.target;
    $("revision").value = data.revision || "";
    setUrl(data.target, data.revision);
    show("intro", false); show("error", false);
    render(data);
  } catch (e) {
    $("error").textContent = "Couldn't open that scan. " + e.message;
    show("error", true);
  }
}

/* ---------- rendering ---------- */

const VERDICT_WORD = { BLOCK: "Blocked: don't load this model", WARN: "Needs review before loading", ALLOW: "Safe to load at this commit" };

function render(rep) {
  state.report = rep;
  state.token = rep.token;
  state.allEvents = false;
  show("result", true);
  const v = String(rep.verdict).toLowerCase();
  $("verdict").className = "verdict v-" + v;
  $("verdict-word").textContent = (rep.verdict === "ALLOW" && !rep.sha) ? "Safe to load" : (VERDICT_WORD[rep.verdict] || rep.verdict);
  renderVerdictLine(rep);
  renderFacts(rep);

  const sb = rep.sandbox || {};
  const iso = $("isolation");
  if (sb.mode === "none" || sb.mode === "subprocess") {
    iso.textContent = "The code was not run in an isolated container" + (sb.note ? ": " + sb.note : ".");
    show("isolation", true);
  } else { show("isolation", false); }

  renderNext(rep);
  renderFilters(rep.findings || []);
  renderFindings();
  renderRefs(rep.references || []);
  renderTimeline();
  renderFiles(rep.files || []);
  loadExplanation(rep);
  window.scrollTo({ top: 0 });
}

function renderVerdictLine(rep) {
  const box = $("verdict-line");
  clear(box);
  if (rep.allowlisted) { box.textContent = "This exact commit and code were approved earlier with a signed allowlist entry."; return; }
  if (rep.verdict === "ALLOW") { box.textContent = "Nothing risky turned up in the code or when it ran in the sandbox."; return; }
  const items = rep.headline ? rep.headline.split("; ") : (rep.reasons || []).slice(0, 4);
  const ul = el("ul", "reasons");
  for (const it of items.slice(0, 4)) {
    const m = /^(\S+?\.\w+) line (\d+):? (.*)$/.exec(it);
    const li = el("li");
    if (m) { li.appendChild(el("span", "mono", `${m[1]}:${m[2]}`)); li.appendChild(document.createTextNode(" " + m[3])); }
    else li.textContent = it;
    ul.appendChild(li);
  }
  const inj = (rep.findings || []).filter((f) => f.rule_id.startsWith("MG070"));
  if (inj.length) {
    const li = el("li", "inj");
    li.appendChild(el("span", "mono", inj[0].file + ":" + [...new Set(inj.map((f) => f.line))].join(",")));
    li.appendChild(document.createTextNode(" contains instructions aimed at AI reviewers (prompt injection). They have no effect on the verdict."));
    ul.appendChild(li);
  }
  box.appendChild(ul);
}

function fact(dl, label, value, copyText) {
  dl.appendChild(el("dt", "", label));
  const dd = el("dd", "", value);
  if (copyText) dd.appendChild(copyButton(copyText));
  dl.appendChild(dd);
}

function renderFacts(rep) {
  const dl = $("facts");
  clear(dl);
  if (rep.sha) fact(dl, "Commit", rep.sha.slice(0, 12), rep.sha);
  else fact(dl, "Source", "local folder");
  if (rep.code_hash) fact(dl, "Code hash", rep.code_hash.slice(0, 12), rep.code_hash);
  const sb = rep.sandbox || {};
  const where = sb.mode === "docker" ? "container" + (sb.strace ? " + strace" : "") : (sb.mode || "?");
  fact(dl, "Run in", where + (sb.status && sb.status !== "ok" ? ` (${sb.status})` : ""));
  fact(dl, "Took", (rep.scan_seconds ?? "?") + "s");
}

function renderNext(rep) {
  const box = $("next");
  clear(box);
  const repoArg = `"${rep.target}"`;
  const revArg = rep.sha ? `, revision="${rep.sha}"` : "";
  const cliRev = rep.sha ? ` --revision ${rep.sha}` : "";
  if (rep.verdict === "ALLOW") {
    box.appendChild(el("h2", "", "Next: load it pinned to this commit"));
    box.appendChild(el("p", "", "Pinning the revision means a later push to the repo can't swap in different code. " +
      "Importing modelgate.auto re-checks the code on every load and refuses anything that changed."));
    box.appendChild(snippet(`import modelgate.auto\nfrom transformers import AutoModel\n\nmodel = AutoModel.from_pretrained(${repoArg}${revArg}, trust_remote_code=True)`));
  } else if (rep.verdict === "WARN") {
    box.appendChild(el("h2", "", "Next: check the findings, then approve this commit if they're expected"));
    box.appendChild(el("p", "", "Approval is tied to this commit and code hash. Any change to the code makes it void."));
    box.appendChild(snippet(`modelgate allow ${rep.target}${cliRev}`));
  } else {
    box.appendChild(el("h2", "", "Next: don't load it"));
    box.appendChild(el("p", "", "With trust_remote_code=True, this code runs as soon as the model is loaded, before you call it. " +
      "If you've read the code yourself and are sure it's a false positive, you can override for this exact commit:"));
    box.appendChild(snippet(`modelgate allow ${rep.target}${cliRev} --force`));
  }
}

function renderFilters(findings) {
  const box = $("filters");
  clear(box);
  const counts = Object.fromEntries(SEV.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  for (const s of SEV) {
    const b = el("button", "filter", `${s[0].toUpperCase() + s.slice(1)} ${counts[s]}`);
    b.type = "button";
    b.disabled = counts[s] === 0;
    b.setAttribute("aria-pressed", String(state.filters.has(s) && counts[s] > 0));
    b.addEventListener("click", () => {
      if (state.filters.has(s)) state.filters.delete(s); else state.filters.add(s);
      renderFilters(findings);
      renderFindings();
    });
    box.appendChild(b);
  }
}

function groupFindings(findings) {
  // file -> line -> [findings]; static and sandbox hits on the same line share one card
  const files = new Map();
  for (const f of findings) {
    const file = f.file || "(repo)";
    if (!files.has(file)) files.set(file, new Map());
    const lines = files.get(file);
    const key = f.line || 0;
    if (!lines.has(key)) lines.set(key, []);
    lines.get(key).push(f);
  }
  const worst = (arr) => Math.min(...arr.map((f) => SEV_RANK[f.severity] ?? 3));
  return [...files.entries()]
    .map(([file, lines]) => ({ file, cards: [...lines.entries()].map(([line, fs]) => ({ line, fs: fs.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]) })) }))
    .map((g) => ({ ...g, rank: Math.min(...g.cards.map((c) => worst(c.fs))) }))
    .sort((a, b) => a.rank - b.rank || a.file.localeCompare(b.file))
    .map((g) => ({ ...g, cards: g.cards.sort((a, b) => worst(a.fs) - worst(b.fs) || a.line - b.line) }));
}

function renderFindings() {
  const rep = state.report;
  const box = $("findings");
  clear(box);
  const all = rep.findings || [];
  const shown = all.filter((f) => state.filters.has(f.severity));
  $("findings-count").textContent = shown.length === all.length ? String(all.length) : `${shown.length} of ${all.length}`;
  if (!all.length) { box.appendChild(el("p", "empty", "No findings. The code didn't do anything the rules look for.")); return; }
  if (!shown.length) { box.appendChild(el("p", "empty", "All findings are hidden by the filters above.")); return; }

  for (const g of groupFindings(shown)) {
    const group = el("div", "file-group");
    const head = el("div", "file-head");
    head.appendChild(el("span", "", g.file));
    const link = hfLink(rep, g.file, 0);
    if (link) { const a = el("a", "", "View on Hugging Face"); a.href = link; a.target = "_blank"; a.rel = "noopener noreferrer"; head.appendChild(a); }
    group.appendChild(head);

    for (const card of g.cards) {
      const c = el("div", "finding");
      for (const f of card.fs) {
        const row = el("div", "finding-head");
        row.appendChild(el("span", "sev sev-" + f.severity, f.severity.charAt(0).toUpperCase() + f.severity.slice(1)));
        row.appendChild(el("span", "ln-ref", card.line ? "L" + card.line : ""));
        const msg = el("div", "msg", f.message);
        const meta = el("span", "meta-line");
        meta.appendChild(el("span", "", (SOURCE_LABEL[f.source] || f.source) + " · "));
        meta.appendChild(el("span", "mono", f.rule_id));
        msg.appendChild(meta);
        row.appendChild(msg);
        c.appendChild(row);
      }
      const withCtx = card.fs.find((f) => f.context && f.context.length);
      if (withCtx) {
        const pre = el("pre", "ctx");
        for (const [n, text] of withCtx.context) {
          const line = el("div", n === card.line ? "hit" : "");
          line.appendChild(el("span", "n", n));
          line.appendChild(document.createTextNode(text));
          pre.appendChild(line);
        }
        c.appendChild(pre);
      } else {
        const snip = card.fs.find((f) => f.snippet);
        if (snip) c.appendChild(el("pre", "ctx-snippet", snip.snippet));
      }
      group.appendChild(c);
    }
    box.appendChild(group);
  }
}

function renderRefs(refs) {
  show("refs-wrap", refs.length > 0);
  const box = $("refs");
  clear(box);
  for (const r of refs) {
    const row = el("div", "ref");
    row.appendChild(el("span", "sev t-" + String(r.verdict).toLowerCase(), r.verdict.charAt(0) + r.verdict.slice(1).toLowerCase()));
    const name = el("span", "mono", r.target + (r.sha ? " @ " + r.sha.slice(0, 12) : ""));
    row.appendChild(name);
    if ((r.reasons || []).length) row.appendChild(el("div", "why", r.reasons.join("; ")));
    box.appendChild(row);
  }
}

function renderTimeline() {
  const sb = (state.report && state.report.sandbox) || {};
  const box = $("timeline");
  clear(box);
  const where = sb.mode === "docker" ? "Offline Docker container, no network, read-only filesystem, fake home directory with decoy keys."
    : sb.mode === "skipped" ? "Not run: " + (sb.note || "skipped") + "."
    : "Mode: " + (sb.mode || "?") + (sb.note ? ". " + sb.note : "");
  $("sandbox-mode").textContent = where;

  const evs = (sb.events || []).filter((e) => e.event !== "module.imported");
  const key = evs.filter((e) => HOT.has(e.event) || e.file);
  const list = state.allEvents ? evs : key;
  const toggle = $("tl-toggle");
  if (evs.length > key.length) {
    toggle.textContent = state.allEvents ? "Show notable only" : `Show all ${evs.length} events`;
    show("tl-toggle", true);
  } else { show("tl-toggle", false); }

  if (!list.length) {
    box.appendChild(el("li", "empty", sb.mode === "docker" ? "Nothing notable: no network, processes, or secret access." : (sb.note || "No events.")));
    return;
  }
  for (const e of list.slice(0, 200)) {
    const li = el("li", HOT.has(e.event) ? "ev hot" : "ev");
    li.appendChild(el("span", "t", "+" + Number(e.t || 0).toFixed(3)));
    const body = el("div");
    body.appendChild(el("span", "what", EVENT_LABEL[e.event] || e.event));
    if (e.file) body.appendChild(el("span", "where", `${e.file}:${e.line}`));
    const extra = [e.source === "strace" ? "kernel" : "python", e.phase].filter(Boolean).join(", ");
    body.appendChild(el("span", "where", extra));
    body.appendChild(el("div", "detail", e.detail));
    li.appendChild(body);
    box.appendChild(li);
  }
}

function renderFiles(files) {
  $("files-count").textContent = String(files.length);
  const ul = $("files");
  clear(ul);
  for (const f of files) ul.appendChild(el("li", "", f));
}

async function loadExplanation(rep) {
  const box = $("explanation");
  clear(box);
  if (rep.explanation) { renderExplanation(rep.explanation); return; }
  const wait = el("p", "waiting", "");
  box.appendChild(wait);
  box.appendChild(el("p", "muted small", "The verdict above is already final. This summary only explains it."));
  const t0 = performance.now();
  const label = rep.llm_enabled ? "Writing summary… " : "Preparing summary… ";
  const iv = setInterval(() => { wait.textContent = label + ((performance.now() - t0) / 1000).toFixed(0) + "s"; }, 250);
  wait.textContent = label;
  const token = rep.token;
  try {
    const r = await fetch("/api/explain?token=" + encodeURIComponent(token));
    const data = await r.json();
    if (state.token !== token) return;   // user moved on to another scan
    if (!r.ok) throw new Error(data.detail || "HTTP " + r.status);
    rep.explanation = data.explanation;
    renderExplanation(data.explanation);
  } catch (e) {
    if (state.token === token) { clear(box); box.appendChild(el("p", "muted", "Summary unavailable: " + e.message)); }
  } finally { clearInterval(iv); }
}

function renderExplanation(x) {
  const box = $("explanation");
  clear(box);
  if (!x) { box.appendChild(el("p", "muted", "No summary.")); return; }
  // split only on sentence punctuation followed by whitespace, so "modeling_x.py" stays intact
  const sentences = String(x.summary || "").split(/(?<=[.!?])\s+/).filter(Boolean);
  const short = sentences.slice(0, 3).join(" ");
  const p = el("p", "", short);
  box.appendChild(p);
  const more = el("div", "hidden");
  if (sentences.length > 3) more.appendChild(el("p", "", sentences.slice(3).join(" ")));
  box.appendChild(more);
  if (x.findings && x.findings.length) {
    const ul = el("ul");
    for (const f of x.findings) {
      const li = el("li");
      li.appendChild(el("span", "loc", `${f.file}:${f.line} `));
      li.appendChild(document.createTextNode(f.explanation));
      ul.appendChild(li);
    }
    more.appendChild(ul);
  }
  if (more.childNodes.length) {
    const b = el("button", "linkish", "Read the full summary");
    b.type = "button";
    b.addEventListener("click", () => { more.classList.toggle("hidden"); b.textContent = more.classList.contains("hidden") ? "Read the full summary" : "Show less"; });
    box.insertBefore(b, more.nextSibling);
  }
  if (x.recommended_action) box.appendChild(el("p", "", "Suggested: " + x.recommended_action));
  if (x.attack_techniques && x.attack_techniques.length) box.appendChild(el("p", "src", "MITRE ATT&CK " + x.attack_techniques.join(", ")));
  const src = String(x.source || "?");
  box.appendChild(el("p", "src", src === "template" ? "Generated from a template (no LLM configured)." : "Written by " + src.replace(/^openrouter:/, "") + "."));
}

/* ---------- wiring ---------- */

$("scan-form").addEventListener("submit", (ev) => { ev.preventDefault(); runScan(); });
$("tl-toggle").addEventListener("click", () => { state.allEvents = !state.allEvents; renderTimeline(); });
document.addEventListener("keydown", (ev) => {
  const typing = ["INPUT", "TEXTAREA"].includes(document.activeElement && document.activeElement.tagName);
  if (ev.key === "/" && !typing) { ev.preventDefault(); $("repo").focus(); $("repo").select(); }
});

loadFixtures();
loadHistory();
(() => {
  const p = new URLSearchParams(location.search);
  if (p.get("repo")) { $("repo").value = p.get("repo"); $("revision").value = p.get("rev") || ""; runScan(); }
})();
