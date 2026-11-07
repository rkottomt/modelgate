"""Render slides/deck/index.html to slides/ModelGate_slides.pdf (video slide becomes a link to the shared video)."""
import base64, pathlib, sys
from playwright.sync_api import sync_playwright
ROOT = pathlib.Path(__file__).resolve().parents[1]
import os
VIDEO = os.environ.get("MG_VIDEO_URL", "https://drive.google.com/file/d/1TpmjCylmENX_av-aFXLQxYK8aIzde66x/view?usp=sharing")
OUT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "ModelGate_slides.pdf"
url = (ROOT / "deck" / "index.html").as_uri()
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1600, "height": 900}, device_scale_factor=2)
    pg.goto(url); n = pg.evaluate("document.querySelectorAll('.slide').length")
    shots, video_pages = [], set()
    for i in range(1, n + 1):
        pg.goto(f"{url}#{i}"); pg.reload(); pg.wait_for_timeout(300)
        pg.evaluate("document.getElementById('hint').style.display='none'")
        if pg.evaluate("!!document.querySelector('.slide.on video')"):
            video_pages.add(i)
            pg.evaluate("""(u) => { const v = document.getElementById('demo'); const a = document.createElement('a'); a.href = u;
              a.style.cssText = 'position:relative;display:block;width:1320px;height:742px;border-radius:4px;overflow:hidden;background:#000 url(poster.jpg) center/cover';
              const play = document.createElement('div'); play.textContent = '▶  Watch the demo';
              play.style.cssText = 'position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);background:#1c1d1f;color:#fff;font:700 34px system-ui;padding:22px 34px;border-radius:6px';
              a.appendChild(play); v.replaceWith(a); }""", VIDEO)
            pg.wait_for_timeout(400)
        shots.append(base64.b64encode(pg.screenshot()).decode())
    pages = "".join(f'<div class="pg"><img src="data:image/png;base64,{s}">' + (f'<a class="hot" href="{VIDEO}"></a>' if i + 1 in video_pages else "") + "</div>" for i, s in enumerate(shots))
    html = f"""<!doctype html><html><head><style>@page {{ size: 1600px 900px; margin: 0 }} body {{ margin: 0 }}
      .pg {{ position: relative; width: 1600px; height: 900px; page-break-after: always; overflow: hidden }} .pg img {{ width: 1600px; height: 900px; display: block }}
      .hot {{ position: absolute; left: 140px; top: 120px; width: 1320px; height: 742px }}</style></head><body>{pages}</body></html>"""
    pg2 = b.new_page(); pg2.set_content(html); pg2.wait_for_timeout(500)
    pg2.pdf(path=str(OUT), width="1600px", height="900px", print_background=True)
    b.close()
print("wrote", OUT, n, "pages")
