"""End-to-end scan pipeline: fetch -> static -> sandbox -> policy -> (advisory) explain."""
from __future__ import annotations

import copy
import json
import re
import time
from pathlib import Path

from . import explain as explain_mod
from . import policy, sandbox, static
from .fetch import fetch


def reports_dir() -> Path:
    d = policy._home() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def repo_key(target: str) -> str:
    p = Path(target).expanduser()
    return f"local:{p.resolve()}" if p.is_dir() else target


def scan(target: str, revision: str | None = None, use_llm: bool = True, sandbox_mode: str | None = None,
         use_allowlist: bool = True) -> dict:
    t0 = time.time()
    bundle = fetch(target, revision)
    key = repo_key(target)
    report: dict = {
        "target": target, "repo_key": key, "revision": revision, "code_hash": bundle.code_hash,
        "bundle": bundle.to_dict(), "modules_executed": bundle.local_modules,
    }

    if use_allowlist and policy.is_allowlisted(key, revision, bundle.code_hash):
        report.update(verdict=policy.ALLOW, reasons=["allowlisted (repo + revision + code hash match)"], findings=[],
                      sandbox=sandbox.SandboxResult("skipped", True, "skipped", None, 0.0, note="allowlisted").to_dict(),
                      allowlisted=True, explanation=None)
    else:
        findings = static.scan(bundle)
        sb = sandbox.run(bundle, force_mode=sandbox_mode)
        findings = policy.sort_findings(findings + policy.sandbox_findings(sb))
        verdict, reasons = policy.decide(findings)   # <- final. Computed before any LLM call.
        report.update(verdict=verdict, reasons=reasons, findings=[f.to_dict() for f in findings],
                      sandbox=sb.to_dict(), allowlisted=False)
        if use_llm:
            # The explainer gets a deep copy; nothing it returns is read back into the verdict.
            report["explanation"] = explain_mod.explain(copy.deepcopy(report))
        else:
            report["explanation"] = None

    report["scan_seconds"] = round(time.time() - t0, 2)
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", key)[-80:]
    path = reports_dir() / f"{name}-{bundle.code_hash[:12]}.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    report["report_path"] = str(path)
    return report
