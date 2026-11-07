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
const secs = (x) => (x == null ? "?" : x < 0.05 ? "<0.1 s" : Number(x).toFixed(1) + " s");
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : (w.endsWith("ch") ? "es" : "s")}`;

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const EXAMPLES = {
  deferred_model: "payload fires only in forward(), on a GPU",
  sneaky_model: "reverse shell and key theft on import",
  injection_model: "tries to talk the AI reviewer out of it",
  cross_repo_model: "pulls code from another repo",
  warn_model: "network library, never called on load",
  clean_model: "plain model code",
};
const ORDER = ["deferred_model", "sneaky_model", "injection_model", "cross_repo_model", "warn_model", "clean_model"];

function category(e) {
  const ev = e.event;
  if (["socket.connect", "net.connect", "socket.getaddrinfo"].includes(ev)) return "net";
  if (["subprocess.Popen", "process.execve", "os.system", "os.exec", "os.posix_spawn", "os.spawn"].includes(ev)) return "proc";
  if (["open", "file.open"].includes(ev)) return "file";
  if (ev === "env.read") return "env";
  if (["os.memfd_create", "memfd_create"].includes(ev)) return "memfd";
  if (ev === "prctl.set_name") return "procname";
  if (ev === "canary.exfil") return "exfil";
  if (["exec", "compile"].includes(ev)) return "dyn";
  if (ev === "ctypes.dlopen") return "native";
  return null;
}
const CAT_LABEL = {
  net: "Opened a network connection", proc: "Started a program", file: "Opened a file",
  env: "Read a secret environment variable", memfd: "Made an in-memory executable", procname: "Renamed its process",
  exfil: "Sent a planted secret out", dyn: "Ran code built at runtime", native: "Loaded a native library",
};
const PHASES = [["import", "import"], ["config", "config"], ["model_init", "model init"], ["forward", "forward pass"],
  ["save", "save"], ["tokenizer", "tokenizer"]];

const state = { report: null, token: null, seq: 0, showLow: false, allEvents: false, timer: null };

/* ---------- helpers ---------- */

function copyButton(text, label) {
  const b = el("button", "copy", label || "Copy");
  b.type = "button";
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); b.textContent = "Copied"; }
    catch (_) { b.textContent = "Select and copy"; }
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
function hfLink(rep, file, line) {
  if (rep.is_fixture || !rep.sha || !file || file.startsWith("(")) return null;
  const parts = rep.target.split("/").map(encodeURIComponent).join("/");
  return `https://huggingface.co/${parts}/blob/${rep.sha}/${file.split("/").map(encodeURIComponent).join("/")}` + (line ? `#L${line}` : "");
}
function prettyError(msg) {
  return String(msg)
    .replace(/\bMG\d{3}-[a-z0-9+-]+:?\s*/g, "")
    .replace(/RepositoryNotFoundError/g, "repository not found")
    .replace(/RevisionNotFoundError/g, "revision not found")
    .replace(/GatedRepoError/g, "gated repo (needs access)")
    .replace(/EntryNotFoundError/g, "file not found");
}
function loc(file, line) { return line && line !== "0" ? `${file}:${line}` : file; }

/* ---------- rail ---------- */

async function loadFixtures() {
  try {
    const data = await (await fetch("/api/fixtures")).json();
    const box = $("fixtures");
    clear(box);
    const rank = (f) => (ORDER.includes(f) ? ORDER.indexOf(f) : 99);
    for (const f of [...data.fixtures].sort((a, b) => rank(a) - rank(b))) {
      const li = el("li");
      const b = el("button", "example");
      b.type = "button";
      b.dataset.example = f;
      b.appendChild(el("span", "name", f.replace(/_/g, " ")));
      if (EXAMPLES[f]) b.appendChild(el("span", "desc", EXAMPLES[f]));
      li.appendChild(b);
      box.appendChild(li);
    }
  } catch (_) { /* optional */ }
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
      const b = el("button", "recent" + (state.token === s.token ? " current" : ""));
      b.type = "button";
      b.title = `${s.target}: ${s.verdict}`;
      b.appendChild(el("span", "dot v-" + String(s.verdict).toLowerCase()));
      b.appendChild(el("span", "name", s.target.replace(/^fixtures\//, "").replace(/_/g, " ")));
      b.addEventListener("click", () => openReport(s.token));
      li.appendChild(b);
      box.appendChild(li);
    }
  } catch (_) { /* ignore */ }
}

function busy(on) {
  $("go").disabled = on;
  document.querySelectorAll(".rail button, [data-example]").forEach((b) => { b.disabled = on; });
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
  const seq = ++state.seq;
  busy(true);
  show("intro", false); show("result", false); show("error", false); show("progress", true);
  $("progress-text").textContent = `Running ${repo} in an offline container with a fake GPU…`;
  const t0 = performance.now();
  clearInterval(state.timer);
  state.timer = setInterval(() => { $("progress-time").textContent = ((performance.now() - t0) / 1000).toFixed(1) + " s"; }, 100);
  try {
    const r = await fetch("/api/scan?" + params.toString());
    const data = await r.json().catch(() => ({}));
    if (seq !== state.seq) return;
    if (!r.ok) throw new Error(data.detail || "The server returned HTTP " + r.status);
    render(data);
    loadHistory();
  } catch (e) {
    if (seq !== state.seq) return;
    $("error").textContent = `Couldn't scan ${repo}. ${e.message}`;
    show("error", true);
  } finally {
    if (seq === state.seq) { clearInterval(state.timer); show("progress", false); busy(false); }
  }
}

async function openReport(token) {
  const seq = ++state.seq;
  try {
    const r = await fetch("/api/report?token=" + encodeURIComponent(token));
    const data = await r.json();
    if (seq !== state.seq) return;
    if (!r.ok) throw new Error(data.detail || "not found");
    $("repo").value = data.target;
    $("revision").value = data.revision || "";
    setUrl(data.target, data.revision);
    show("intro", false); show("error", false);
    render(data);
    loadHistory();
  } catch (e) {
    $("error").textContent = "Couldn't open that scan. " + e.message;
    show("error", true);
  }
}

/* ---------- render ---------- */

const WORD = { BLOCK: "Blocked: don't load this model", WARN: "Needs review before loading", ALLOW: "Safe to load at this commit" };

function noCustomCode(rep) {
  const sb = rep.sandbox || {};
  return sb.mode === "skipped" && /no local remote-code/.test(sb.note || "");
}

function render(rep) {
  state.report = rep;
  state.token = rep.token;
  state.allEvents = false;
  show("result", true);
  $("verdict").className = "verdict v-" + String(rep.verdict).toLowerCase();
  $("verdict-word").textContent = rep.verdict === "ALLOW" && !rep.sha ? "Safe to load" : (WORD[rep.verdict] || rep.verdict);
  renderVerdictLine(rep);
  renderMeta(rep);
  const sb = rep.sandbox || {};
  if (sb.mode === "none" || sb.mode === "subprocess") {
    $("isolation").textContent = "The code was not run in an isolated container" + (sb.note ? ": " + sb.note : ".");
    show("isolation", true);
  } else { show("isolation", false); }
  renderStages(rep);
  renderSandbox();
  renderFindings();
  renderRefs(rep.references || []);
  renderNext(rep);
  renderFiles(rep.files || []);
  loadExplanation(rep);
  window.scrollTo({ top: 0 });
}

function renderVerdictLine(rep) {
  const box = $("verdict-line");
  clear(box);
  if (rep.allowlisted) { box.textContent = "This exact commit and code were approved earlier with a signed allowlist entry."; return; }
  if (rep.verdict === "ALLOW") {
    box.textContent = noCustomCode(rep) ? "This repo has no custom code, so loading it only runs transformers' own built-in code."
      : "Nothing risky turned up in the code or when it ran in the sandbox.";
    return;
  }
  const findings = rep.findings || [];
  const items = rep.headline ? rep.headline.split("; ") : (rep.reasons || []).slice(0, 4);
  const ul = el("ul", "reasons");
  for (const raw of items.slice(0, 4)) {
    const it = prettyError(raw);
    const li = el("li");
    const m = /^(\S+?\.\w+) line (\d+):? (.*)$/.exec(it) || /^(?:[A-Z]+\d*-[\w+-]+\s+)?(\S+?\.\w+):(\d+)\s+(.*)$/.exec(it);
    const m2 = !m && /^(?:[A-Z]+\d*-[\w+-]+\s+)?(\S+?\.(?:py|json))\s+(.*)$/.exec(it);
    if (m) {
      const [, file, line, rest] = m;
      li.appendChild(el("span", "mono", loc(file, line)));
      li.appendChild(document.createTextNode(" " + rest.replace(/\s*\[deferred trigger:[^\]]*\]/, "")));
      const d = findings.find((f) => f.file === file && String(f.line) === line && /fired during (\w+)/.test(f.message));
      if (d) li.appendChild(el("span", "deferred", ` · only fired during ${/fired during (\w+)/.exec(d.message)[1]}(), not on import`));
    } else if (m2) {
      li.appendChild(el("span", "mono", m2[1]));
      li.appendChild(document.createTextNode(" " + m2[2]));
    } else {
      li.textContent = it.replace(/^[A-Z]+\d*-[\w+-]+\s+/, "");
    }
    ul.appendChild(li);
  }
  const inj = findings.filter((f) => f.rule_id.startsWith("MG070"));
  if (inj.length) {
    const li = el("li", "inj");
    li.appendChild(el("span", "mono", inj[0].file + ":" + [...new Set(inj.map((f) => f.line))].join(",")));
    li.appendChild(document.createTextNode(" contains instructions aimed at AI reviewers. They have no effect on the verdict."));
    ul.appendChild(li);
  }
  box.appendChild(ul);
}

function renderMeta(rep) {
  const box = $("verdict-meta");
  clear(box);
  const add = (label, value, full) => {
    const s = el("span", "meta-item");
    s.appendChild(el("span", "muted", label + " "));
    s.appendChild(el("span", "mono", value));
    if (full) s.appendChild(copyButton(full));
    box.appendChild(s);
  };
  if (rep.sha) add("commit", rep.sha.slice(0, 12), rep.sha); else add("source", "local folder");
  if (rep.code_hash) add("code hash", rep.code_hash.slice(0, 12), rep.code_hash);
  add("total", secs(rep.scan_seconds));
}

function renderStages(rep) {
  const ol = $("stages");
  clear(ol);
  const t = rep.timings || {};
  const sb = rep.sandbox || {};
  const findings = rep.findings || [];
  const behaviours = groupEvents(sb.events || [], false).filter((r) => r.cat);
  const kernel = behaviours.filter((r) => r.kernel).length;
  const crit = findings.filter((f) => f.severity === "critical").length;
  const review = findings.filter((f) => f.severity === "high" || f.severity === "medium").length;
  const stage = (n, name, result, time, cls) => {
    const li = el("li", "stage" + (cls ? " " + cls : ""));
    const top = el("div", "stage-top");
    top.appendChild(el("span", "stage-n", n));
    top.appendChild(el("span", "stage-name", name));
    top.appendChild(el("span", "stage-time num", time));
    li.appendChild(top);
    li.appendChild(el("div", "stage-result", result));
    ol.appendChild(li);
  };
  const nFiles = (rep.files || []).length;
  stage("1", "Fetched", `${plural(nFiles, "file")}, code only` + (rep.sha ? `, commit ${rep.sha.slice(0, 8)}` : ", local folder"), secs(t.fetch));
  stage("2", "Read the code", rep.static_count != null ? plural(rep.static_count, "match") : "-", secs(t.static));
  let ran;
  if (sb.mode === "docker") ran = "offline container, fake GPU, decoy keys: " + (behaviours.length ? `${plural(behaviours.length, "risky action")}, ${kernel} confirmed by the kernel` : "no risky actions");
  else if (noCustomCode(rep)) ran = "nothing to run: no custom code";
  else if (sb.mode === "skipped") ran = "not run: " + (sb.note || "skipped");
  else ran = "not run: no isolated sandbox, so blocked";
  stage("3", "Ran it", ran, sb.mode === "docker" ? secs(t.sandbox ?? sb.duration) : "-", behaviours.length ? "hot" : "");
  stage("4", "Decided", crit ? `${plural(crit, "critical finding")}: Block` : review ? `${plural(review, "finding")} to review: Warn` : "nothing risky: Allow",
    secs(t.policy), "d-" + String(rep.verdict).toLowerCase());
}

function groupEvents(evs, all) {
  const rows = [];
  for (const e of evs.filter((x) => x.source !== "strace")) {
    const cat = category(e);
    if (!cat && !all) continue;
    rows.push({ t: e.t, cat, py: e, kernel: null, phase: e.phase });
  }
  for (const k of evs.filter((x) => x.source === "strace")) {
    const cat = category(k);
    const match = rows.find((r) => r.cat && r.cat === cat && !r.kernel && Math.abs((r.t || 0) - (k.t || 0)) < 0.02);
    if (match) match.kernel = k;
    else rows.push({ t: k.t, cat, py: null, kernel: k, phase: null });
  }
  return rows.sort((a, b) => (a.t || 0) - (b.t || 0));
}

function prettyEvent(ev) {
  return { "sandbox.start": "Sandbox started", "sandbox.end": "Sandbox finished", "module.imported": "Imported the repo's module",
    "exercise.error": "A step couldn't run", "module.error": "Import failed", "exercise.note": "Note", "import": "Imported a library",
    "module.missing_dependency": "Missing dependency" }[ev] || ev.replace(/^phase\./, "Ran: ").replace(/_/g, " ");
}

function renderSandbox() {
  const rep = state.report;
  const sb = rep.sandbox || {};
  const evs = sb.events || [];
  const ex = $("exercised");
  clear(ex);
  if (sb.mode === "docker") {
    const ran = new Set(evs.filter((e) => e.event.startsWith("phase.")).map((e) => e.event.slice(6)));
    if (evs.some((e) => e.event === "module.imported")) ran.add("import");
    const errs = evs.filter((e) => e.event === "exercise.error" || e.event === "module.error");
    const gpu = evs.some((e) => /fake GPU/.test(e.detail || ""));
    ex.appendChild(el("span", "muted", "Exercised "));
    PHASES.forEach(([key, label], i) => {
      if (i) ex.appendChild(el("span", "sep", "→"));
      const ok = ran.has(key);
      const s = el("span", ok ? "ph ok" : "ph miss", label + (key === "import" && gpu ? " (GPU faked)" : ""));
      const err = errs.find((e) => (e.detail || "").includes(`(${key === "model_init" ? "model" : key})`));
      if (!ok) s.title = err ? "not reached: " + err.detail : "not reached";
      ex.appendChild(s);
    });
  } else {
    ex.textContent = noCustomCode(rep) ? "Nothing to run: the repo has no custom code." : (sb.note || "The code was not run.");
  }

  const box = $("timeline");
  clear(box);
  const keyRows = groupEvents(evs, false).filter((r) => r.cat);
  const allRows = groupEvents(evs, true);
  const rows = state.allEvents ? allRows : keyRows;
  const toggle = $("tl-toggle");
  toggle.textContent = state.allEvents ? "Show risky actions only" : `Show all ${allRows.length} events`;
  show("tl-toggle", sb.mode === "docker" && allRows.length > keyRows.length);
  if (sb.mode !== "docker") return;
  if (!rows.length) {
    const errs = evs.filter((e) => e.event === "exercise.error" || e.event === "module.error").length;
    box.appendChild(el("li", "empty", errs ? `No network, programs or secret access seen, but ${plural(errs, "step")} couldn't run, so some code paths went unobserved.`
      : "No network, programs or secret access seen."));
    return;
  }
  for (const r of rows) {
    const li = el("li", r.cat ? "ev hot" : "ev");
    li.appendChild(el("span", "t num", "+" + Number(r.t || 0).toFixed(3) + "s"));
    const body = el("div");
    const e = r.py || r.kernel;
    body.appendChild(el("span", "what", r.cat ? CAT_LABEL[r.cat] : prettyEvent(e.event)));
    body.appendChild(el("div", "detail", (r.kernel && r.cat === "net" ? r.kernel.detail : e.detail) || ""));
    const prov = el("div", "prov");
    if (r.kernel) prov.appendChild(el("span", "src k", "kernel"));
    if (r.py && r.cat) prov.appendChild(el("span", "src p", "python"));
    if (r.py && r.py.file) prov.appendChild(el("span", "mono", loc(r.py.file, r.py.line)));
    if (r.cat && r.phase && r.phase !== "import") prov.appendChild(el("span", "phase-tag", "during " + r.phase.replace("_", " ")));
    if (r.kernel && !r.py && r.cat) prov.appendChild(el("span", "muted", "kernel only"));
    if (prov.childNodes.length) body.appendChild(prov);
    li.appendChild(body);
    box.appendChild(li);
  }
}

function renderFindings() {
  const rep = state.report;
  const box = $("findings");
  clear(box);
  const all = rep.findings || [];
  const minor = all.filter((f) => f.severity === "medium" || f.severity === "low").length;
  const shown = all.filter((f) => state.showLow || f.severity === "critical" || f.severity === "high")
    .sort((a, b) => (a.line || 0) - (b.line || 0) || SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  $("findings-count").textContent = String(all.length);
  $("sev-toggle").textContent = state.showLow ? "Hide medium and low" : `Show medium and low (${minor})`;
  show("sev-toggle", minor > 0);
  if (!all.length) { box.appendChild(el("p", "empty", "No findings.")); return; }
  if (!shown.length) { box.appendChild(el("p", "empty", "Only medium or low findings. Use the toggle to see them.")); return; }

  const sandboxLines = new Set(all.filter((f) => f.source === "sandbox").map((f) => f.file + ":" + f.line));
  const byFile = new Map();
  for (const f of shown) { if (!byFile.has(f.file)) byFile.set(f.file, []); byFile.get(f.file).push(f); }
  for (const [file, fs] of byFile) {
    const group = el("div", "file-group");
    const head = el("div", "file-head");
    head.appendChild(el("span", "mono", file));
    const link = hfLink(rep, file, 0);
    if (link) { const a = el("a", "", "View on Hugging Face"); a.href = link; a.target = "_blank"; a.rel = "noopener noreferrer"; head.appendChild(a); }
    group.appendChild(head);

    const lines = new Map();
    const hits = new Set(fs.map((f) => f.line));
    for (const f of fs) for (const [n, text] of f.context || []) lines.set(n, text);
    if (lines.size) {
      const pre = el("pre", "ctx");
      let prev = null;
      for (const n of [...lines.keys()].sort((a, b) => a - b)) {
        if (prev !== null && n > prev + 1) pre.appendChild(el("div", "gap", "⋯"));
        const row = el("div", hits.has(n) ? "hit" : "");
        row.appendChild(el("span", "n", n));
        row.appendChild(document.createTextNode(lines.get(n)));
        pre.appendChild(row);
        prev = n;
      }
      group.appendChild(pre);
    }
    const table = el("table", "ftable");
    for (const f of fs) {
      const tr = el("tr");
      tr.appendChild(el("td", "sev sev-" + f.severity, f.severity));
      tr.appendChild(el("td", "mono ln", f.line ? "L" + f.line : ""));
      const td = el("td", "msg");
      td.appendChild(document.createTextNode(prettyError(f.message.replace(/\s*\[deferred trigger:[^\]]*\]/, ""))));
      const how = f.source === "sandbox" ? "seen when run" : f.source === "static" ? "found in code" : f.source;
      td.appendChild(el("span", "meta-line", how + (f.source === "static" && sandboxLines.has(f.file + ":" + f.line) ? ", confirmed when run" : "") + " · " + f.rule_id));
      tr.appendChild(td);
      table.appendChild(tr);
    }
    group.appendChild(table);
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
    row.appendChild(el("span", "mono", r.target + (r.sha ? " @ " + r.sha.slice(0, 12) : "")));
    if ((r.reasons || []).length) row.appendChild(el("div", "why", prettyError(r.reasons.join("; "))));
    box.appendChild(row);
  }
}

function renderNext(rep) {
  const box = $("next");
  clear(box);
  const revArg = rep.sha ? `, revision="${rep.sha}"` : "";
  const cliRev = rep.sha ? ` --revision ${rep.sha}` : "";
  if (rep.verdict === "ALLOW") {
    box.appendChild(el("h2", "", "Load it pinned to this commit"));
    box.appendChild(el("p", "", "A later push can't swap the code: the import re-checks it on every load."));
    box.appendChild(snippet(`import modelgate.auto\nfrom transformers import AutoModel\n\nmodel = AutoModel.from_pretrained(\n    "${rep.target}"${revArg},\n    trust_remote_code=True)`));
  } else if (rep.verdict === "WARN") {
    box.appendChild(el("h2", "", "Review, then approve this commit"));
    box.appendChild(el("p", "", "Approval is tied to this commit and code hash. Any change to the code voids it."));
    box.appendChild(snippet(`modelgate allow ${rep.target}${cliRev}`));
  } else {
    box.appendChild(el("h2", "", "Don't load it"));
    box.appendChild(el("p", "", "This code would run as soon as the model loads, before you call it. Pick a different model."));
    const p = el("p", "muted small", "Sure it's a false positive after reading the code? ");
    p.appendChild(el("code", "", `modelgate allow ${rep.target} --force`));
    box.appendChild(p);
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
  const wait = el("p", "muted", "Writing summary…");
  box.appendChild(wait);
  const t0 = performance.now();
  const iv = setInterval(() => { wait.textContent = "Writing summary… " + ((performance.now() - t0) / 1000).toFixed(0) + " s"; }, 500);
  const token = rep.token;
  try {
    const r = await fetch("/api/explain?token=" + encodeURIComponent(token));
    const data = await r.json();
    if (state.token !== token) return;
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
  const sentences = String(x.summary || "").split(/(?<=[.!?])\s+/).filter(Boolean);
  box.appendChild(el("p", "", sentences.slice(0, 3).join(" ")));
  const more = el("div", "hidden");
  if (sentences.length > 3) more.appendChild(el("p", "", sentences.slice(3).join(" ")));
  if (x.recommended_action) more.appendChild(el("p", "", "Suggested: " + x.recommended_action));
  if (x.attack_techniques && x.attack_techniques.length) more.appendChild(el("p", "src", "MITRE ATT&CK " + x.attack_techniques.join(", ")));
  if (more.childNodes.length) {
    const b = el("button", "linkish", "Read more");
    b.type = "button";
    b.addEventListener("click", () => { more.classList.toggle("hidden"); b.textContent = more.classList.contains("hidden") ? "Read more" : "Show less"; });
    box.appendChild(b);
  }
  box.appendChild(more);
  const src = String(x.source || "?");
  box.appendChild(el("p", "src", src === "template" ? "From a template (no LLM configured)." : "Written by " + src.replace(/^openrouter:/, "") + " after the verdict was decided."));
}

/* ---------- wiring ---------- */

$("scan-form").addEventListener("submit", (ev) => { ev.preventDefault(); runScan(); });
$("tl-toggle").addEventListener("click", () => { state.allEvents = !state.allEvents; renderSandbox(); });
$("sev-toggle").addEventListener("click", () => { state.showLow = !state.showLow; renderFindings(); });
document.addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-example]");
  if (!b || b.disabled) return;
  $("repo").value = "fixtures/" + b.dataset.example;
  $("revision").value = "";
  runScan();
});
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
