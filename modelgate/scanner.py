"""End-to-end scan pipeline: fetch(pinned SHA) -> static -> sandbox -> policy -> referenced repos -> (advisory) explain.

Any internal failure produces a BLOCK (fail closed).
"""
from __future__ import annotations

import copy
import json
import re
import time
import traceback
from pathlib import Path

from . import explain as explain_mod
from . import policy, sandbox, static
from .fetch import fetch
from .static import Finding

MAX_REF_DEPTH = 3
MAX_REF_REPOS = 10


def reports_dir() -> Path:
    d = policy._home() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def repo_key(target: str) -> str:
    p = Path(target).expanduser()
    return f"local:{p.resolve()}" if p.is_dir() else target


def _fail_closed(report: dict, rule: str, msg: str) -> dict:
    f = Finding(rule, "critical", "(scanner)", 0, "", msg + " (fail closed)", source="manifest")
    report.setdefault("findings", []).append(f.to_dict())
    report["verdict"], report["reasons"] = policy.BLOCK, [f"{rule} {msg}"]
    report.setdefault("sandbox", sandbox.SandboxResult("skipped", True, "skipped", None, 0.0, note="not run").to_dict())
    return report


def _save(report: dict) -> dict:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", report["repo_key"])[-80:]
    path = reports_dir() / f"{name}-{(report.get('code_hash') or 'nohash')[:12]}.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    report["report_path"] = str(path)
    return report


def scan(target: str, revision: str | None = None, use_llm: bool = True, sandbox_mode: str | None = None,
         use_allowlist: bool = True, _depth: int = 0, _visited: set | None = None) -> dict:
    t0 = time.time()
    visited = _visited if _visited is not None else set()
    key = repo_key(target)
    visited.add(key)
    report: dict = {"target": target, "repo_key": key, "revision": revision, "sha": None, "code_hash": "",
                    "findings": [], "references": [], "explanation": None, "allowlisted": False}

    try:
        bundle = fetch(target, revision)
    except Exception as e:  # noqa: BLE001  (network errors, missing repo, bad revision...)
        _fail_closed(report, "MG004-fetch-failed", f"could not fetch {target}@{revision or 'main'}: {type(e).__name__}")
        report["scan_seconds"] = round(time.time() - t0, 2)
        return _save(report)

    report.update(sha=bundle.sha, code_hash=bundle.code_hash, bundle=bundle.to_dict(),
                  modules_executed=bundle.local_modules)

    if use_allowlist and policy.is_allowlisted(key, bundle.sha, bundle.code_hash):
        report.update(verdict=policy.ALLOW, reasons=["allowlisted (repo + pinned SHA + code hash match a signed entry)"],
                      sandbox=sandbox.SandboxResult("skipped", True, "skipped", None, 0.0, note="allowlisted").to_dict(),
                      allowlisted=True)
        report["scan_seconds"] = round(time.time() - t0, 2)
        return _save(report)

    try:
        findings = static.scan(bundle)
        sb = sandbox.run(bundle, force_mode=sandbox_mode)
        findings += policy.sandbox_findings(sb)
        report["sandbox"] = sb.to_dict()

        # Follow code references into other repos (cross-repo auto_map, custom_pipelines, custom_generate)
        for other in bundle.other_repos:
            if other in visited:
                continue
            if _depth + 1 > MAX_REF_DEPTH or len(visited) >= MAX_REF_REPOS:
                findings.append(Finding("MG063-ref-depth", "critical", "config.json", 0, other,
                                        f"reference chain too deep/wide at `{other}` (fail closed)", source="reference"))
                continue
            child = scan(other, None, use_llm=False, sandbox_mode=sandbox_mode, use_allowlist=use_allowlist,
                         _depth=_depth + 1, _visited=visited)
            report["references"].append({k: child.get(k) for k in ("target", "sha", "code_hash", "verdict", "report_path")}
                                        | {"reasons": child.get("reasons", [])[:3]})
            if child["verdict"] == policy.BLOCK:
                findings.append(Finding("MG062-ref-blocked", "critical", "config.json", 0, other,
                                        f"referenced repo `{other}` is BLOCKED: {'; '.join(child['reasons'][:2])}", source="reference"))
            elif child["verdict"] == policy.WARN:
                findings.append(Finding("MG062-ref-warn", "high", "config.json", 0, other,
                                        f"referenced repo `{other}` has warnings ({len(child['findings'])} findings)", source="reference"))

        findings = policy.sort_findings(findings)
        verdict, reasons = policy.decide(findings)   # <- final. Computed before any LLM call.
        report.update(verdict=verdict, reasons=reasons, findings=[f.to_dict() for f in findings])
    except Exception as e:  # noqa: BLE001
        report["internal_error"] = traceback.format_exc(limit=3)[-800:]
        _fail_closed(report, "MG005-internal-error", f"scanner error: {type(e).__name__}")

    if use_llm:
        # The explainer gets a deep copy; nothing it returns is read back into the verdict.
        report["explanation"] = explain_mod.explain(copy.deepcopy(report))
    report["scan_seconds"] = round(time.time() - t0, 2)
    return _save(report)
