"use strict";
// Agent guardrails page. All server/LLM strings are inserted with textContent only.

const $ = (id) => document.getElementById(id);
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
function show(id, on) { $(id).classList.toggle("hidden", !on); }

const EVENT_LABEL = {
  "socket.connect": "Opened a network connection", "net.connect": "Opened a network connection",
  "socket.getaddrinfo": "Looked up a hostname", "subprocess.Popen": "Started a program", "process.execve": "Started a program",
  "os.system": "Ran a shell command", "open": "Opened a file", "file.open": "Opened a file",
  "env.read": "Read a secret environment variable", "os.memfd_create": "Made an in-memory file",
  "exec": "Ran generated code", "compile": "Built code at runtime", "agent.start": "Agent started",
  "agent.error": "Agent crashed", "resources": "Resource use", "sandbox.end": "Sandbox finished",
};
const HOT = new Set(["socket.connect", "net.connect", "subprocess.Popen", "process.execve", "os.system", "env.read",
  "os.memfd_create", "file.open", "open", "exec", "canary.exfil"]);

const state = { agents: [], agent: null, rails: [], runs: [] };

async function getJSON(url, opts) {
  const r = await fetch(url, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || "HTTP " + r.status);
  return data;
}

async function init() {
  const data = await getJSON("/api/agents");
  state.agents = data.agents;
  const box = $("agents");
  clear(box);
  for (const a of data.agents) {
    const li = el("li");
    const b = el("button");
    b.type = "button";
    b.appendChild(el("span", "name", a.name.replace(/_/g, " ")));
    b.addEventListener("click", () => selectAgent(a.id));
    li.appendChild(b);
    box.appendChild(li);
  }
  const want = new URLSearchParams(location.search).get("agent");
  if (want && data.agents.some((a) => a.id === want)) selectAgent(want);
}

function selectAgent(id) {
  const a = state.agents.find((x) => x.id === id);
  state.agent = a;
  history.replaceState(null, "", "?agent=" + encodeURIComponent(id));
  show("intro", false); show("agent", true); show("step2", false); show("step3", false);
  $("agent-name").textContent = a.name.replace(/_/g, " ");
  $("agent-files").textContent = "runs " + a.entry + " · files: " + a.files.join(", ");
  $("goal").value = a.goal || "";
  $("propose-status").textContent = "";
}

/* ---------- step 1 → 2: draft ---------- */

async function propose() {
  const btn = $("propose");
  btn.disabled = true;
  const t0 = performance.now();
  const iv = setInterval(() => { $("propose-status").textContent = "Drafting… " + ((performance.now() - t0) / 1000).toFixed(0) + "s"; }, 250);
  try {
    const data = await getJSON("/api/agents/propose", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent: state.agent.id, goal: $("goal").value }),
    });
    state.rails = data.guardrails;
    $("draft-summary").textContent = data.summary || "";
    $("draft-source").textContent = data.source === "template" ? "default list (no AI configured)"
      : "AI draft · " + String(data.source).replace(/^openrouter:/, "");
    renderRails();
    show("step2", true); show("step3", false);
    $("propose-status").textContent = "";
    $("step2").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    $("propose-status").textContent = "Couldn't draft guardrails: " + e.message;
  } finally { clearInterval(iv); btn.disabled = false; }
}

function paramInput(rail, name, value) {
  const wrap = el("label", "param");
  wrap.appendChild(el("span", "muted small", name + " "));
  const isList = Array.isArray(value);
  const input = el("input");
  input.type = isList ? "text" : "number";
  input.value = isList ? value.join(", ") : String(value);
  input.spellcheck = false;
  if (isList) input.placeholder = name === "hosts" ? "api.example.com, pypi.org" : "/usr/bin/git";
  input.addEventListener("change", () => {
    rail.params[name] = isList ? input.value.split(",").map((s) => s.trim()).filter(Boolean) : Number(input.value);
  });
  wrap.appendChild(input);
  return wrap;
}

function renderRails() {
  const ul = $("rails");
  clear(ul);
  for (const r of state.rails) {
    const li = el("li", "rail-item" + (r.enabled ? " on" : ""));
    const label = el("label", "rail-check");
    const cb = el("input");
    cb.type = "checkbox";
    cb.checked = !!r.enabled;
    cb.addEventListener("change", () => { r.enabled = cb.checked; li.classList.toggle("on", cb.checked); });
    label.appendChild(cb);
    const text = el("span");
    text.appendChild(el("strong", "", r.title));
    text.appendChild(el("span", "muted small", " " + r.desc));
    label.appendChild(text);
    li.appendChild(label);
    const names = Object.keys(r.params || {});
    if (names.length) {
      const p = el("div", "params");
      for (const n of names) p.appendChild(paramInput(r, n, r.params[n]));
      li.appendChild(p);
    }
    if (r.why && r.why !== "default") li.appendChild(el("p", "why small", "AI: " + r.why));
    ul.appendChild(li);
  }
}

/* ---------- step 2 → 3: approve + run ---------- */

async function run() {
  const btn = $("run");
  btn.disabled = true;
  $("run-status").textContent = "Running in the sandbox…";
  try {
    const rep = await getJSON("/api/agents/run", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent: state.agent.id, guardrails: state.rails }),
    });
    renderRun(rep);
    state.runs.unshift({ agent: rep.agent, verdict: rep.verdict, n: (rep.findings || []).length });
    renderRuns();
    $("run-status").textContent = "";
    $("step3").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    $("run-status").textContent = "Run failed: " + e.message;
  } finally { btn.disabled = false; }
}

function renderRuns() {
  const ul = $("runs");
  clear(ul);
  for (const r of state.runs.slice(0, 12)) {
    const li = el("li", "run-row");
    li.appendChild(el("span", "dot v-" + r.verdict.toLowerCase()));
    li.appendChild(el("span", "name", r.agent + (r.n ? ` · ${r.n} violations` : " · clean")));
    ul.appendChild(li);
  }
}

function fact(dl, k, v) { dl.appendChild(el("dt", "", k)); dl.appendChild(el("dd", "", v)); }

function renderRun(rep) {
  show("step3", true);
  const bad = rep.verdict !== "ALLOW";
  $("verdict").className = "verdict " + (bad ? "v-block" : "v-allow");
  const n = (rep.findings || []).length;
  $("verdict-word").textContent = !rep.contract_valid ? "Not run: contract invalid"
    : bad ? `Stopped: ${n} guardrail violation${n === 1 ? "" : "s"}` : "Stayed within its guardrails";
  const line = $("verdict-line");
  clear(line);
  if (bad) {
    const ul = el("ul", "reasons");
    for (const r of (rep.reasons || []).slice(0, 5)) ul.appendChild(el("li", "", r));
    line.appendChild(ul);
  } else {
    line.textContent = "Every network call, file write, program start and secret read was checked. Nothing broke the contract.";
  }
  const dl = $("facts");
  clear(dl);
  const res = rep.resources || {};
  fact(dl, "Enforced", `${rep.guardrails.filter((g) => g.enabled).length} of ${rep.guardrails.length} guardrails`);
  fact(dl, "Wall time", (res.wall_s ?? "?") + "s");
  fact(dl, "CPU", (res.cpu_s ?? "?") + "s");
  fact(dl, "Peak memory", (res.max_rss_mb ?? "?") + " MB");
  fact(dl, "Contract", rep.contract ? "signed " + rep.contract.mac.slice(0, 10) : "-");

  const box = $("violations");
  clear(box);
  $("viol-count").textContent = String(n);
  if (!n) box.appendChild(el("p", "empty", "None."));
  for (const f of rep.findings || []) {
    const c = el("div", "finding");
    const head = el("div", "finding-head");
    head.appendChild(el("span", "sev sev-critical", "Violation"));
    head.appendChild(el("span", "ln-ref", f.line ? "L" + f.line : ""));
    const msg = el("div", "msg", f.message);
    const meta = el("span", "meta-line");
    meta.appendChild(el("span", "mono", f.file + (f.line ? ":" + f.line : "") + " · " + f.rule_id));
    msg.appendChild(meta);
    head.appendChild(msg);
    c.appendChild(head);
    if (f.context && f.context.length) {
      const pre = el("pre", "ctx");
      for (const [ln, text] of f.context) {
        const row = el("div", ln === f.line ? "hit" : "");
        row.appendChild(el("span", "n", ln));
        row.appendChild(document.createTextNode(text));
        pre.appendChild(row);
      }
      c.appendChild(pre);
    }
    box.appendChild(c);
  }

  const tl = $("timeline");
  clear(tl);
  const evs = ((rep.sandbox || {}).events || []).filter((e) => e.event !== "sandbox.start");
  if (!evs.length) tl.appendChild(el("li", "empty", (rep.sandbox || {}).note || "No events."));
  for (const e of evs.slice(0, 120)) {
    const li = el("li", HOT.has(e.event) ? "ev hot" : "ev");
    li.appendChild(el("span", "t", "+" + Number(e.t || 0).toFixed(3)));
    const body = el("div");
    body.appendChild(el("span", "what", EVENT_LABEL[e.event] || e.event));
    if (e.file) body.appendChild(el("span", "where", `${e.file}:${e.line}`));
    body.appendChild(el("span", "where", e.source === "strace" ? "kernel" : "python"));
    body.appendChild(el("div", "detail", e.detail));
    li.appendChild(body);
    tl.appendChild(li);
  }
}

$("propose").addEventListener("click", propose);
$("run").addEventListener("click", run);
init().catch((e) => { $("intro").appendChild(el("p", "error", "Couldn't load agents: " + e.message)); });
