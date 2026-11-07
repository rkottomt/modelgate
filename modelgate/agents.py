"""Run an AI agent inside the ModelGate sandbox under a signed guardrail contract (modelgate run)."""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import guardrails, policy, sandbox
from .fetch import fetch

AGENTS_DIR = Path(__file__).resolve().parents[1] / "examples" / "agents"


def load_meta(agent_dir: str | Path) -> dict:
    d = Path(agent_dir)
    meta = {"name": d.name, "entry": "agent.py", "goal": ""}
    p = d / "agent.json"
    if p.is_file() and p.stat().st_size < 64_000:
        try:
            raw = json.loads(p.read_text())
            meta.update({k: str(raw[k])[:2000] for k in ("name", "entry", "goal") if isinstance(raw.get(k), str)})
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return meta


def propose(agent_dir: str | Path, goal: str | None = None) -> dict:
    bundle = fetch(str(agent_dir))
    meta = load_meta(agent_dir)
    entry = Path(bundle.root) / meta["entry"]
    code = entry.read_text(errors="replace")[:3000] if entry.is_file() and meta["entry"] in bundle.files else ""
    out = guardrails.propose(goal if goal is not None else meta["goal"], sorted(bundle.files), code)
    return out | {"agent": meta["name"], "goal": goal if goal is not None else meta["goal"], "code_hash": bundle.code_hash}


def run(agent_dir: str | Path, contract: dict, force_mode: str | None = None) -> dict:
    t0 = time.time()
    bundle = fetch(str(agent_dir))
    meta = load_meta(agent_dir)
    rails = guardrails.normalize(contract.get("guardrails"))
    report = {"agent": meta["name"], "goal": meta["goal"], "entry": meta["entry"], "code_hash": bundle.code_hash,
              "guardrails": [g.to_dict() for g in rails], "contract_valid": True}

    problems = []
    if not guardrails.verify(contract):
        problems.append("the guardrail contract's signature is invalid (edited after approval)")
    elif contract.get("code_hash") != bundle.code_hash:
        problems.append("the agent's code changed after the guardrails were approved")
    if problems:
        report.update(contract_valid=False, verdict=policy.BLOCK, reasons=[p + " (fail closed)" for p in problems],
                      findings=[], sandbox=sandbox.SandboxResult("skipped", True, "skipped", None, 0.0,
                                                                  note="not run: contract invalid").to_dict(),
                      resources={}, run_seconds=round(time.time() - t0, 2))
        return report

    sb = sandbox.run_agent(bundle, meta["entry"], force_mode=force_mode)
    findings = guardrails.check(rails, sb)
    verdict = policy.BLOCK if findings else policy.ALLOW
    reasons = [f"{f.file}:{f.line} {f.message}" if f.line else f.message for f in findings[:6]]
    report.update(verdict=verdict, reasons=reasons or ["no guardrail was violated"],
                  findings=[f.to_dict() for f in findings], sandbox=sb.to_dict(),
                  resources=guardrails.resources(sb), run_seconds=round(time.time() - t0, 2))
    return report
