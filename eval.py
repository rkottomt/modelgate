"""ModelGate evaluation: all fixtures + popular real trust_remote_code repos (code only, never weights).

Usage: python eval.py [--no-real] [--json out.json]
Real popular repos are presumed benign: any BLOCK on them is a false positive and is reported as such.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from modelgate.scanner import scan

ROOT = Path(__file__).resolve().parent
FIXTURES = {
    "clean_model": "ALLOW", "warn_model": "WARN", "sneaky_model": "BLOCK", "injection_model": "BLOCK",
    "deferred_model": "BLOCK", "cross_repo_model": "BLOCK",
}
# Popular repos that load custom code via auto_map (pinned to whatever main resolves to at eval time).
REAL = [
    "microsoft/Phi-3-mini-4k-instruct",
    "THUDM/chatglm3-6b",
    "nomic-ai/nomic-embed-text-v1.5",      # cross-repo hop -> nomic-ai/nomic-bert-2048
    "deepseek-ai/DeepSeek-V3",
    "Qwen/Qwen-7B-Chat",
    "jinaai/jina-embeddings-v3",           # cross-repo hop -> jinaai/xlm-roberta-flash-implementation
]


def row(name: str, r: dict, expected: str | None) -> dict:
    sev = Counter(f["severity"] for f in r.get("findings", []))
    return {
        "repo": name, "sha": (r.get("sha") or "")[:12], "verdict": r["verdict"], "expected": expected,
        "critical": sev["critical"], "high": sev["high"], "medium": sev["medium"],
        "rules": sorted({f["rule_id"] for f in r.get("findings", []) if f["severity"] in ("critical", "high", "medium")}),
        "sandbox": f"{r.get('sandbox', {}).get('mode')}/{r.get('sandbox', {}).get('status')}",
        "refs": [f"{x['target']}={x['verdict']}" for x in r.get("references", [])],
        "seconds": r.get("scan_seconds"),
        "top_reasons": r.get("reasons", [])[:3],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-real", action="store_true")
    ap.add_argument("--json", default=str(ROOT / "eval_results.json"))
    args = ap.parse_args()
    os.environ.setdefault("MODELGATE_LLM", "off")   # eval measures the deterministic gate only
    con = Console()
    rows = []
    for fx, exp in FIXTURES.items():
        r = scan(str(ROOT / "fixtures" / fx), use_llm=False, use_allowlist=False)
        rows.append(row(f"fixtures/{fx}", r, exp) | {"kind": "fixture"})
        con.print(f"[dim]{fx}: {r['verdict']} ({r['scan_seconds']}s)[/]")
    if not args.no_real:
        for repo in REAL:
            t0 = time.time()
            r = scan(repo, use_llm=False, use_allowlist=False)
            rows.append(row(repo, r, None) | {"kind": "real"})
            con.print(f"[dim]{repo}: {r['verdict']} ({round(time.time() - t0, 1)}s)[/]")

    t = Table(title="ModelGate eval", expand=True)
    for c in ("Repo", "Verdict", "Expected", "C/H/M", "Sandbox", "Time (s)", "Rules / notes"):
        t.add_column(c, overflow="fold")
    color = {"BLOCK": "red", "WARN": "yellow", "ALLOW": "green"}
    for x in rows:
        exp = x["expected"] or ("benign" if x["kind"] == "real" else "")
        ok = (x["expected"] == x["verdict"]) if x["expected"] else (x["verdict"] != "BLOCK")
        notes = ", ".join(x["rules"][:8]) + (f"  refs: {', '.join(x['refs'])}" if x["refs"] else "")
        t.add_row(x["repo"], f"[{color[x['verdict']]}]{x['verdict']}[/]", f"{exp} {'✓' if ok else '✗'}",
                  f"{x['critical']}/{x['high']}/{x['medium']}", x["sandbox"], str(x["seconds"]), notes)
    con.print(t)

    fx = [x for x in rows if x["kind"] == "fixture"]
    real = [x for x in rows if x["kind"] == "real"]
    con.print(f"Fixtures correct: {sum(x['verdict'] == x['expected'] for x in fx)}/{len(fx)}")
    if real:
        fps = [x for x in real if x["verdict"] == "BLOCK"]
        con.print(f"Real repos: {Counter(x['verdict'] for x in real)}  ·  false-positive BLOCKs: {len(fps)}/{len(real)}")
        for x in fps:
            con.print(f"  [red]FP[/] {x['repo']}: {x['top_reasons']}")
    Path(args.json).write_text(json.dumps(rows, indent=2))
    con.print(f"[dim]wrote {args.json}[/]")


if __name__ == "__main__":
    main()
