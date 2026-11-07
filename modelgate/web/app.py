"""ModelGate dashboard: FastAPI + one static page.

Security: every repo/LLM string is rendered client-side with textContent (never innerHTML),
the page has no inline script/style, and a strict CSP is sent on every response.
Only HF repo ids or bundled fixture names can be scanned (no arbitrary local paths).
"""
from __future__ import annotations

import copy
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from .. import agents as agents_mod
from .. import explain as explain_mod
from .. import guardrails as gr
from ..hook import _headline
from ..scanner import scan

STATIC = Path(__file__).parent
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
REPO_RE = re.compile(r"^[A-Za-z0-9][\w.-]{0,95}/[\w.-]{1,96}$")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

MAX_KEPT = 50
CONTEXT_LINES = 3
_reports: OrderedDict[str, dict] = OrderedDict()   # token -> report (in-memory, this process only)
_explained: dict[tuple, dict] = {}                # (sha, code_hash, verdict) -> explanation; same code => same input
_lock = threading.Lock()

app = FastAPI(title="ModelGate", docs_url=None, redoc_url=None)


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def _fixtures() -> list[str]:
    return sorted(p.name for p in FIXTURES.iterdir() if p.is_dir()) if FIXTURES.is_dir() else []


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html", media_type="text/html")


@app.get("/agents")
def agents_page():
    return FileResponse(STATIC / "agents.html", media_type="text/html")


@app.get("/static/{name}")
def static(name: str):
    allowed = {"app.js": "text/javascript", "agents.js": "text/javascript", "style.css": "text/css"}
    if name not in allowed:
        raise HTTPException(404)
    return FileResponse(STATIC / name, media_type=allowed[name])


@app.get("/api/fixtures")
def fixtures():
    return {"fixtures": _fixtures()}


def _context(root: str | None, rel: str, line: int) -> list[list] | None:
    """A few lines around a finding, read from the scanned snapshot (never outside it)."""
    if not root or not line or not rel or rel.startswith("("):
        return None
    real_root = os.path.realpath(root)
    full = os.path.realpath(os.path.join(real_root, rel))
    if os.path.commonpath([real_root, full]) != real_root or not os.path.isfile(full) or os.path.islink(full):
        return None
    if os.path.getsize(full) > 2 * 1024 * 1024:
        return None
    try:
        lines = Path(full).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    lo, hi = max(1, line - CONTEXT_LINES), min(len(lines), line + CONTEXT_LINES)
    return [[n, lines[n - 1][:300]] for n in range(lo, hi + 1)]


def _resolve(repo: str) -> str:
    if repo.startswith("fixtures/") and repo.split("/", 1)[1] in _fixtures():
        return str(FIXTURES / repo.split("/", 1)[1])
    if REPO_RE.match(repo) and ".." not in repo:
        return repo
    raise HTTPException(400, "Enter a Hugging Face repo id like org/name, or pick one of the examples.")


@app.get("/api/scan")
def api_scan(repo: str = Query(..., max_length=200), revision: str | None = Query(None, max_length=100)):
    target = _resolve(repo.strip())
    if revision is not None and not re.fullmatch(r"[\w./-]{1,100}", revision):
        raise HTTPException(400, "Revision can only contain letters, digits, '.', '/', '_' and '-'.")
    # The LLM explanation is fetched separately (/api/explain) so the verdict is never held up by it.
    report = scan(target, revision, use_llm=False)
    report.pop("internal_error", None)
    bundle = report.pop("bundle", None) or {}
    root = bundle.get("root")
    for f in report.get("findings", []):
        f["context"] = _context(root, f.get("file", ""), f.get("line") or 0)
    report["files"] = sorted((bundle.get("files") or {}).keys())
    report["target"] = repo
    report["is_fixture"] = repo.startswith("fixtures/")
    report["headline"] = _headline(report) if report.get("verdict") != "ALLOW" else ""
    report["llm_enabled"] = explain_mod.llm_config() is not None
    token = secrets.token_urlsafe(12)
    report["token"] = token
    report["scanned_at"] = time.time()
    with _lock:
        _reports[token] = report
        while len(_reports) > MAX_KEPT:
            _reports.popitem(last=False)
    return JSONResponse(report)


@app.get("/api/explain")
def api_explain(token: str = Query(..., max_length=40)):
    with _lock:
        report = _reports.get(token)
    if report is None:
        raise HTTPException(404, "Scan not found (the server may have restarted). Run the scan again.")
    if report.get("explanation") is None:
        key = (report.get("sha"), report.get("code_hash"), report.get("verdict"))
        cached = _explained.get(key) if report.get("code_hash") else None
        if cached is None:
            # deep copy: nothing the explainer returns flows back into the verdict
            cached = explain_mod.explain(copy.deepcopy(report))
            if cached.get("source") != "template" or not explain_mod.llm_config():
                _explained[key] = cached
        report["explanation"] = cached
    return JSONResponse({"verdict": report["verdict"], "explanation": report["explanation"]})


@app.get("/api/history")
def api_history():
    with _lock:
        items = list(_reports.values())[::-1]
    return {"scans": [{k: r.get(k) for k in ("token", "target", "revision", "verdict", "sha", "scanned_at")}
                      for r in items]}


@app.get("/api/report")
def api_report(token: str = Query(..., max_length=40)):
    with _lock:
        report = _reports.get(token)
    if report is None:
        raise HTTPException(404, "Scan not found. Run it again.")
    return JSONResponse(report)


# ---------------- agents: guardrail contracts + sandboxed runs ----------------

def _agent_dir(name) -> Path:
    if not isinstance(name, str) or not re.fullmatch(r"[\w-]{1,64}", name):
        raise HTTPException(400, "Unknown agent.")
    d = agents_mod.AGENTS_DIR / name
    if not d.is_dir():
        raise HTTPException(404, "Unknown agent.")
    return d


@app.get("/api/agents")
def api_agents():
    out = []
    if agents_mod.AGENTS_DIR.is_dir():
        for d in sorted(p for p in agents_mod.AGENTS_DIR.iterdir() if p.is_dir()):
            meta = agents_mod.load_meta(d)
            out.append({"id": d.name, "name": meta["name"], "goal": meta["goal"], "entry": meta["entry"],
                        "files": sorted(p.name for p in d.iterdir() if p.is_file())})
    return {"agents": out, "catalog": {k: {"title": v["title"], "desc": v["desc"]} for k, v in gr.CATALOG.items()},
            "llm_enabled": explain_mod.llm_config() is not None}


@app.post("/api/agents/propose")
def api_propose(body: dict = Body(...)):
    d = _agent_dir(body.get("agent"))
    goal = body.get("goal")
    goal = goal[:2000] if isinstance(goal, str) else None
    return JSONResponse(agents_mod.propose(d, goal))


@app.post("/api/agents/run")
def api_run(body: dict = Body(...)):
    d = _agent_dir(body.get("agent"))
    # Clicking "Run" in the UI is the human approval: the ticked set is normalized and signed here, then checked.
    bundle_hash = agents_mod.fetch(str(d)).code_hash
    contract = gr.sign(d.name, bundle_hash, body.get("guardrails"))
    report = agents_mod.run(d, contract)
    for f in report.get("findings", []):
        f["context"] = _context(str(d), f.get("file", ""), f.get("line") or 0)
    report["contract"] = {k: contract[k] for k in ("approved_at", "mac")}
    return JSONResponse(report)
