import html, re, textwrap
from playwright.sync_api import sync_playwright
import os
S = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build"); os.makedirs(S, exist_ok=True)
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
L = open(S + "/demo_out.txt").read().splitlines()
def esc(s): return html.escape(s)
red, grn, dim, ylw = "#ff6b61", "#7fd18b", "#8b8e95", "#e5c07b"
out = []
out.append(f'<span style="color:{grn}">$</span> MODELGATE_LLM=off python examples/demo_load.py fixtures/sneaky_model')
out.append(esc(L[1]))
for l in L[2:7]:
    out.append(esc(l).replace("BLOCK", f'<b style="color:{red}">BLOCK</b>'))
for l in L[7:21]:   # findings title, header, first 5 sandbox rows
    e = esc(l).replace("CRITICAL", f'<span style="color:{red}">CRITICAL</span>')
    out.append(e)
w=len(L[80]); txt="… 17 more findings (static rules + combos) trimmed for the slide …"
out.append(esc(L[79].replace("│","├").replace("┃","├")[:0]) + "├" + "─"*(w-2) + "┤")
out.append("│ " + f'<span style="color:{dim}">{txt}</span>' + " "*(w-3-len(txt)) + "│")
out.append("└" + "─"*(w-2) + "┘")
for l in L[81:103]:
    e = esc(l)
    e = e.replace("│ strace │", f'│ <span style="color:{ylw}">strace</span> │')
    out.append(e)
out.append(f'<span style="color:{dim}">… AI explanation panel (advisory; does not affect verdict) trimmed …</span>')
last = re.sub(r"\x1b\[[0-9;]*m", "", L[123]).replace(os.path.expanduser("~"), "~")
last = last.replace(" BLOCKED ", "", 1)
wrapped = textwrap.wrap(last, 128)
out.append(f'<span style="background:#b3261e;color:#fff;font-weight:700"> BLOCKED </span> ' + esc(wrapped[0]))
out += [esc(w) for w in wrapped[1:]]
body = "\n".join(out)
page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#e9e7e1;padding:28px;display:inline-block}}
.win{{background:#1c1d1f;border-radius:10px;box-shadow:0 1px 0 #bdb9ae;overflow:hidden}}
.bar{{height:30px;background:#2a2b2e;display:flex;align-items:center;padding:0 12px;gap:8px;color:#9a9ca1;font:12px -apple-system,system-ui,sans-serif}}
.d{{width:11px;height:11px;border-radius:50%;background:#55575c}}
.t{{flex:1;text-align:center;margin-right:50px}}
pre{{margin:0;padding:16px 20px 20px;color:#e6e6e3;font:13px/1.17 "SF Mono",Menlo,Consolas,monospace;white-space:pre}}
</style></head><body><div class="win"><div class="bar"><span class="d"></span><span class="d"></span><span class="d"></span><span class="t">import modelgate.auto: load blocked before the model code ran on the host</span></div><pre>{body}</pre></div></body></html>"""
open(S + "/term.html", "w").write(page)
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1300, "height": 800}, device_scale_factor=2)
    pg.goto("file://" + S + "/term.html")
    pg.locator("body").screenshot(path=REPO + "/slides/images/terminal_import_hook.png")
    b.close()
