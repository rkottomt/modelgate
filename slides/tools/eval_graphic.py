import json, html
from playwright.sync_api import sync_playwright
import os
S = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build"); os.makedirs(S, exist_ok=True)
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
rows = json.load(open(REPO + "/eval_results.json"))
NOTE = {
 "fixtures/clean_model": "plain model code",
 "fixtures/warn_model": "optional requests helper",
 "fixtures/sneaky_model": "connect, decoy key, canary, /bin/sh, memfd",
 "fixtures/injection_model": "same + 4 prompt-injection comments",
 "fixtures/deferred_model": "payload fires only in forward() with GPU",
 "fixtures/cross_repo_model": "referenced repo unfetchable: fail closed",
 "microsoft/Phi-3-mini-4k-instruct": "module-level try block",
 "THUDM/chatglm3-6b": "false positive: base64+bz2 CUDA kernel via ctypes",
 "nomic-ai/nomic-embed-text-v1.5": "cross-repo hop, ref = WARN",
 "deepseek-ai/DeepSeek-V3": "false positive: import crash on transformers 5",
 "Qwen/Qwen-7B-Chat": "runs nvcc via subprocess at import",
 "jinaai/jina-embeddings-v3": "cross-repo hop, ref = ALLOW",
}
C = {"BLOCK": "#b3261e", "WARN": "#8a5300", "ALLOW": "#1e6b3a"}
maxs = max(r["seconds"] for r in rows)
def tr(r):
    v = r["verdict"]; exp = r.get("expected")
    if r["kind"] == "fixture":
        ok = "correct" if v == exp else "wrong"; exps = exp
    else:
        exps = "benign"; ok = "false positive" if v == "BLOCK" else "ok"
    okc = "fp" if ok in ("false positive", "wrong") else ""
    bar = f'<span class="bar" style="width:{r["seconds"]/maxs*90:.0f}px"></span>{r["seconds"]:.1f}'
    return (f'<tr><td class="mono">{html.escape(r["repo"])}</td>'
            f'<td><b style="color:{C[v]}">{v}</b></td><td>{exps}</td><td class="{okc}">{ok}</td>'
            f'<td class="num">{r["critical"]} / {r["high"]} / {r["medium"]}</td>'
            f'<td class="num">{bar}</td><td class="note">{html.escape(NOTE.get(r["repo"], ""))}</td></tr>')
fx = [r for r in rows if r["kind"] == "fixture"]; real = [r for r in rows if r["kind"] != "fixture"]
nfx = sum(r["verdict"] == r["expected"] for r in fx)
cnt = {k: sum(r["verdict"] == k for r in real) for k in C}
def strip(label, n, total, color):
    return f'<div class="seg" style="flex:{n};background:{color}">{label} {n}</div>' if n else ""
page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#f6f5f1;color:#1c1d1f;font:15px -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;padding:36px 40px;width:1360px}}
h1{{font-size:26px;margin:0 0 6px}} .sub{{color:#4a4b4f;margin:0 0 26px}}
.cards{{display:flex;gap:20px;margin-bottom:26px}}
.card{{background:#fff;border:1.5px solid #bdb9ae;border-radius:8px;padding:16px 20px;flex:1}}
.card .k{{color:#4a4b4f;font-size:14px}} .card .v{{font-size:30px;font-weight:700;margin-top:4px}}
.stack{{display:flex;height:28px;border-radius:4px;overflow:hidden;margin-top:10px;width:100%}}
.seg{{color:#fff;font-size:13px;font-weight:600;display:flex;align-items:center;padding-left:10px}}
table{{border-collapse:collapse;width:100%;background:#fff;border:1.5px solid #bdb9ae;border-radius:8px}}
th{{text-align:left;font-size:13px;color:#4a4b4f;font-weight:600;padding:10px 12px;border-bottom:1.5px solid #bdb9ae}}
td{{padding:9px 12px;border-bottom:1px solid #e4e1d8;vertical-align:middle}}
tr.sep td{{background:#f6f5f1;font-size:13px;color:#4a4b4f;font-weight:600;padding:6px 12px}}
.mono{{font-family:'SF Mono',Menlo,monospace;font-size:13.5px}} .num{{font-variant-numeric:tabular-nums;white-space:nowrap}}
.bar{{display:inline-block;height:10px;background:#bdb9ae;margin-right:8px;vertical-align:middle;border-radius:2px}}
.note{{color:#4a4b4f;font-size:13.5px}} .fp{{color:#b3261e;font-weight:600}}
.foot{{color:#6b6c70;font-size:13px;margin-top:14px}}
</style></head><body>
<h1>Eval: fixtures and popular real repos</h1>
<p class="sub">From eval_results.json (python eval.py). Code-only downloads, real repos pinned to the SHA <span class="mono">main</span> resolved to on 2026-11-07. Docker sandbox, Apple-silicon Mac.</p>
<div class="cards">
 <div class="card"><div class="k">Fixtures (harmless imitations)</div><div class="v">{nfx}/{len(fx)} correct</div></div>
 <div class="card" style="flex:1.6"><div class="k">Real repos ({len(real)}), all believed benign</div>
  <div class="stack">{strip("WARN", cnt["WARN"], len(real), C["WARN"])}{strip("BLOCK", cnt["BLOCK"], len(real), C["BLOCK"])}{strip("ALLOW", cnt["ALLOW"], len(real), C["ALLOW"])}</div>
  <div class="k" style="margin-top:6px">{cnt["WARN"]} WARN · {cnt["BLOCK"]} BLOCK (false positives) · {cnt["ALLOW"]} ALLOW</div></div>
 <div class="card"><div class="k">Time per scan</div><div class="v">{min(r["seconds"] for r in rows):.1f}–{maxs:.1f} s</div></div>
</div>
<table><tr><th>Repo</th><th>Verdict</th><th>Expected</th><th>Result</th><th>Crit / High / Med</th><th>Seconds</th><th>Why</th></tr>
<tr class="sep"><td colspan="7">Fixtures</td></tr>{''.join(tr(r) for r in fx)}
<tr class="sep"><td colspan="7">Real repos</td></tr>{''.join(tr(r) for r in real)}
</table>
<p class="foot">WARN is the expected state for real custom code; approving a specific SHA + code hash (HMAC-signed allowlist) is the intended workflow.</p>
</body></html>"""
open(S + "/eval.html", "w").write(page)
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
    pg.goto("file://" + S + "/eval.html")
    pg.locator("body").screenshot(path=REPO + "/slides/images/eval.png")
    b.close()
