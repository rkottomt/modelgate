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

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from .. import explain as explain_mod
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


@app.get("/static/{name}")
def static(name: str):
    allowed = {"app.js": "text/javascript", "style.css": "text/css"}
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
        # deep copy: nothing the explainer returns flows back into the verdict
        report["explanation"] = explain_mod.explain(copy.deepcopy(report))
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
