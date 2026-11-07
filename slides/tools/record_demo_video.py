"""Record the ModelGate workflow demo: real HF model blocked -> different model allowed -> agent guardrails -> run."""
import base64
import json
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import imageio_ffmpeg
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
OUT = Path(sys.argv[1])
WORK = OUT.parent / "wframes"
W, H = 1440, 810
GOOD = "Qwen/Qwen2.5-0.5B-Instruct"
GOAL = ("Summarise sales.csv by region and write report.json to the workspace. "
        "It doesn't need the internet, other programs, or any credentials.")

# warm the AI summaries (cached per commit + code hash) so the scan pages don't sit on "Writing summary"
import os
for r in ():
    rep = json.load(urllib.request.urlopen(f"{BASE}/api/scan?repo={r}", timeout=300))
    urllib.request.urlopen(f"{BASE}/api/explain?token={rep['token']}", timeout=300).read()
    print("warmed", r, rep["verdict"], flush=True)

OVERLAY = """
() => {
  if (document.getElementById('mg-cap')) return;
  const cap = document.createElement('div'); cap.id = 'mg-cap';
  Object.assign(cap.style, {position:'fixed', left:'0', right:'0', bottom:'0', padding:'16px 32px 18px',
    background:'rgba(20,21,22,.94)', color:'#f4f2ed', font:'600 21px/1.35 system-ui,-apple-system,sans-serif',
    zIndex: 99999, transition:'opacity .25s', opacity:'0', borderTop:'3px solid #b3261e'});
  document.body.appendChild(cap);
  const cur = document.createElement('div'); cur.id = 'mg-cur';
  const last = window.__mgCur || [720, 420];
  Object.assign(cur.style, {position:'fixed', left: last[0] + 'px', top: last[1] + 'px', width:'22px', height:'22px', marginLeft:'-11px',
    marginTop:'-11px', borderRadius:'50%', border:'2px solid #1c1d1f', background:'rgba(255,255,255,.55)',
    boxShadow:'0 0 0 2px rgba(255,255,255,.8)', zIndex: 100000, pointerEvents:'none',
    transition:'left .55s cubic-bezier(.3,.7,.3,1), top .55s cubic-bezier(.3,.7,.3,1), transform .12s'});
  document.body.appendChild(cur);
}
"""
cur_pos = [720, 420]


def overlay(page):
    page.evaluate(OVERLAY)
    page.evaluate("p => { const c = document.getElementById('mg-cur'); if (!c) return; c.style.transition = 'none'; c.style.left = p[0]+'px'; c.style.top = p[1]+'px'; c.offsetHeight; c.style.transition = 'left .55s cubic-bezier(.3,.7,.3,1), top .55s cubic-bezier(.3,.7,.3,1), transform .12s'; }", cur_pos)


def caption(page, text, accent="#b3261e"):
    overlay(page)
    page.evaluate("""([t, a]) => { const c = document.getElementById('mg-cap');
        c.style.opacity = '0'; setTimeout(() => { c.textContent = t; c.style.borderTopColor = a; c.style.opacity = '1'; }, 180); }""",
                  [text, accent])


def move(page, selector):
    overlay(page)
    box = page.locator(selector).first.bounding_box()
    x, y = box["x"] + min(box["width"] / 2, 70), box["y"] + box["height"] / 2
    cur_pos[:] = [x, y]
    page.evaluate("([x, y]) => { const c = document.getElementById('mg-cur'); c.style.left = x + 'px'; c.style.top = y + 'px'; }", [x, y])
    page.wait_for_timeout(600)


def press_fx(page):
    page.evaluate("() => { const c = document.getElementById('mg-cur'); c.style.transform = 'scale(.7)'; setTimeout(() => c.style.transform = '', 140); }")


def click(page, selector):
    move(page, selector)
    press_fx(page)
    page.locator(selector).first.click()


def type_into(page, selector, text, delay=40):
    move(page, selector)
    press_fx(page)
    page.locator(selector).first.click()
    page.keyboard.press("Meta+A")
    page.keyboard.press("Backspace")
    page.keyboard.type(text, delay=delay)


cuts = []  # (start, end) wall-clock intervals removed from the video


def trimmed_wait(fn, head=1.0, tail=0.5):
    t0 = time.time()
    fn()
    t1 = time.time()
    if t1 - t0 > head + tail + 0.3:
        cuts.append((t0 + head, t1 - tail))


def scroll_to(page, selector, offset=90):
    page.evaluate(f"""() => {{ const e = document.querySelector({json.dumps(selector)});
        window.scrollTo({{top: e.getBoundingClientRect().top + window.scrollY - {offset}, behavior: 'smooth'}}); }}""")


END = """<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;background:#f6f5f1;color:#1c1d1f;height:100vh;display:flex;flex-direction:column;justify-content:center;padding:0 120px;box-sizing:border-box;font-family:system-ui,-apple-system,sans-serif}
h1{font-size:54px;margin:0 0 18px;font-weight:700}.rule{width:64px;height:5px;background:#b3261e;margin-bottom:26px}
p{font-size:24px;line-height:1.5;color:#4a4d52;margin:0}
</style></head><body><div class="rule"></div><h1>ModelGate</h1>
<p>Run the model's code in a trap before it runs on your machine.</p><p>One import. About three seconds.</p></body></html>"""

TERMINAL = """<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;background:#f6f5f1;font:16px/1.55 ui-monospace,'SF Mono',Menlo,monospace;color:#1c1d1f;height:100vh;display:flex;flex-direction:column;justify-content:center;padding:0 90px;box-sizing:border-box}
.lbl{font:600 13px system-ui,-apple-system,sans-serif;color:#74777d;margin:0 0 6px}
.ed{background:#fff;border:1px solid #dcd9d1;border-radius:3px;padding:16px 20px;margin-bottom:22px;white-space:pre}
.k{color:#1d4f91}.s{color:#1e6b3a}.c{color:#74777d}.hl{background:#fde9a8}
.term{background:#1b1c1e;color:#e7e5e0;border-radius:3px;padding:16px 20px;min-height:190px;white-space:pre-wrap}
.p{color:#7cc794}.blk{background:#b3261e;color:#fff;font-weight:700;padding:0 6px}.dim{color:#8f9196}
</style></head><body>
<p class="lbl">load_model.py</p>
<div class="ed"><span class="hl"><span class="k">import</span> modelgate.auto</span>   <span class="c"># the only line you add</span>
<span class="k">from</span> transformers <span class="k">import</span> AutoModel

model = AutoModel.from_pretrained(<span class="s">"fixtures/sneaky_model"</span>, trust_remote_code=<span class="k">True</span>)</div>
<p class="lbl">Terminal</p>
<div class="term" id="term"><span class="p">$ </span><span id="cmd"></span></div>
</body></html>"""
BLOCKED_TEXT = ("ModelGate BLOCKED fixtures/sneaky_model: modeling_x.py line 3 attempts socket.connect to "
                "203.0.113.5:4444; modeling_x.py line 7 reads decoy ~/.ssh/id_rsa; modeling_x.py line 8: touched "
                "canary credential HF_TOKEN; modeling_x.py line 9 spawns /bin/sh.")


frames = []
with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=2, color_scheme="light")
    page = ctx.new_page()
    page.goto(BASE + "/")

    cdp = ctx.new_cdp_session(page)

    def on_frame(ev):
        frames.append((ev["metadata"]["timestamp"], base64.b64decode(ev["data"])))
        try:
            cdp.send("Page.screencastFrameAck", {"sessionId": ev["sessionId"]})
        except Exception:
            pass
    cdp.on("Page.screencastFrame", on_frame)
    cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 92, "everyNthFrame": 1})
    t_start = time.time()

    def wait_scan():
        page.wait_for_selector("#result:not(.hidden)", timeout=180000)
        page.wait_for_selector("#progress.hidden", state="attached", timeout=180000)

    # 1. a real model from Hugging Face
    page.goto(BASE + "/")
    page.wait_for_selector("#fixtures button")
    caption(page, "Paste a real model from Hugging Face: THUDM/chatglm3-6b.")
    page.wait_for_timeout(900)
    type_into(page, "#repo", "THUDM/chatglm3-6b", delay=35)
    page.wait_for_timeout(200)
    click(page, "#go")
    trimmed_wait(wait_scan, head=1.0, tail=0.2)
    caption(page, "Blocked in about 3 seconds, before any of its code runs on your machine.")
    page.wait_for_timeout(3400)

    # 2. why: the exact line
    caption(page, "Why: line 28 decodes a hidden base64 + bz2 blob and loads it as native code.")
    scroll_to(page, ".col-main .section-head.spaced", 70)
    page.wait_for_timeout(5200)
    caption(page, "Code that unpacks itself at runtime can't be checked, so it won't load.")
    page.wait_for_timeout(3000)

    # 3. a different model: allowed
    scroll_to(page, "body", 0)
    page.wait_for_timeout(400)
    caption(page, "Pick a different model.", "#1e6b3a")
    type_into(page, "#repo", GOOD, delay=30)
    page.wait_for_timeout(200)
    click(page, "#go")
    trimmed_wait(wait_scan, head=0.6, tail=0.2)
    caption(page, "No hidden code: allowed, and pinned to the exact commit that was checked.", "#1e6b3a")
    page.wait_for_timeout(3600)

    # 4. end card
    page.goto("about:blank")
    page.set_content(END)
    page.wait_for_timeout(2000)
    t_end = time.time()
    cdp.send("Page.stopScreencast")
    browser.close()

total_cut = sum(b - a for a, b in cuts)
print(f"captured {len(frames)} frames over {t_end - t_start:.1f}s, cutting {total_cut:.1f}s in {len(cuts)} places", flush=True)


def vt(t):
    return t - sum(min(b, t) - a for a, b in cuts if t > a)


frames.sort(key=lambda f: f[0])
kept = [(vt(t), d) for t, d in frames if not any(a < t < b for a, b in cuts)]
end_v = vt(t_end)
shutil.rmtree(WORK, ignore_errors=True)
WORK.mkdir(parents=True)
lines = []
for i, (t, data) in enumerate(kept):
    fn = WORK / f"f{i:05d}.jpg"
    fn.write_bytes(data)
    nxt = kept[i + 1][0] if i + 1 < len(kept) else max(end_v, t + 0.5)
    lines.append(f"file '{fn}'\nduration {max(nxt - t, 1 / 60):.4f}")
lines.append(f"file '{WORK / f'f{len(kept) - 1:05d}.jpg'}'")
(WORK / "list.txt").write_text("\n".join(lines) + "\n")
ff = imageio_ffmpeg.get_ffmpeg_exe()
subprocess.run([ff, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(WORK / "list.txt"),
                "-vf", "scale=1920:1080:flags=lanczos,fps=30,format=yuv420p", "-c:v", "libx264", "-preset", "slow",
                "-crf", "18", "-movflags", "+faststart", str(OUT)], check=True)
print("wrote", OUT)
