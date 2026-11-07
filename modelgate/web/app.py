"""ModelGate dashboard: FastAPI + one static page.

Security: every repo/LLM string is rendered client-side with textContent (never innerHTML),
the page has no inline script/style, and a strict CSP is sent on every response.
Only HF repo ids or bundled fixture names can be scanned (no arbitrary local paths).
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from ..scanner import scan

STATIC = Path(__file__).parent
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
REPO_RE = re.compile(r"^[A-Za-z0-9][\w.-]{0,95}/[\w.-]{1,96}$")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

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


@app.get("/api/scan")
def api_scan(repo: str = Query(..., max_length=200), revision: str | None = Query(None, max_length=100)):
    if repo.startswith("fixtures/") and repo.split("/", 1)[1] in _fixtures():
        target = str(FIXTURES / repo.split("/", 1)[1])
    elif REPO_RE.match(repo) and ".." not in repo:
        target = repo
    else:
        raise HTTPException(400, "repo must be a Hugging Face repo id (org/name) or fixtures/<name>")
    if revision is not None and not re.fullmatch(r"[\w./-]{1,100}", revision):
        raise HTTPException(400, "bad revision")
    report = scan(target, revision)
    report.pop("internal_error", None)
    if "bundle" in report:
        report["bundle"] = {"files": report["bundle"].get("files", {}), "auto_map": report["bundle"].get("auto_map", [])}
    report["target"] = repo
    return JSONResponse(report)
