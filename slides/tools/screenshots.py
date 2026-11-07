import os
from playwright.sync_api import sync_playwright
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "images") + "/"
BASE = "http://127.0.0.1:8000/?repo="
jobs = [("fixtures/clean_model", "dashboard_allow.png"),
        ("fixtures/sneaky_model", "dashboard_block.png"),
        ("fixtures/injection_model", "dashboard_injection.png")]
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2, color_scheme="light")
    for repo, name in jobs:
        pg = ctx.new_page()
        pg.goto(BASE + repo)
        pg.wait_for_selector("#result:not(.hidden)", timeout=120000)
        try:
            pg.wait_for_selector("#explanation .src", timeout=90000)
        except Exception as e:
            print("no explanation src for", repo, e)
        pg.wait_for_timeout(500)
        pg.screenshot(path=OUT + name)
        print("saved", name)
        if repo.endswith("sneaky_model"):
            box = pg.evaluate("""() => {
              const g=document.querySelector('#findings .file-group');
              const els=[g.querySelector('.file-head'), ...[...g.querySelectorAll('.finding')].slice(0,2)];
              const r=els.map(e=>e.getBoundingClientRect());
              const x=Math.min(...r.map(a=>a.left))-12, y=Math.min(...r.map(a=>a.top))+window.scrollY-12;
              return {x, y, width:Math.max(...r.map(a=>a.right))+12-x, height:Math.max(...r.map(a=>a.bottom))+window.scrollY+12-y};
            }""")
            pg.screenshot(path=OUT + "findings_code_context.png", clip=box, full_page=True)
            # timeline section: union of section-head, sandbox-mode, timeline
            box = pg.evaluate("""() => {
              const heads=[...document.querySelectorAll('.col-side .section-head')];
              const h=heads.find(x=>x.textContent.includes('What the code did'));
              const els=[h, document.getElementById('sandbox-mode'), document.getElementById('timeline')];
              let r=els.map(e=>e.getBoundingClientRect());
              const x=Math.min(...r.map(a=>a.left))-12, y=Math.min(...r.map(a=>a.top))+window.scrollY-12;
              const w=Math.max(...r.map(a=>a.right))+12-x, hh=Math.max(...r.map(a=>a.bottom))+window.scrollY+12-y;
              return {x, y, width:w, height:hh};
            }""")
            pg.screenshot(path=OUT + "timeline.png", clip=box, full_page=True)
            print("timeline box", box)
        pg.close()
    b.close()
