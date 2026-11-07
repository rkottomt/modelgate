"""Screenshots of the Agent guardrails page (needs `modelgate serve` on :8000)."""
import os
from playwright.sync_api import sync_playwright

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "images") + "/"
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2, color_scheme="light").new_page()
    pg.goto("http://127.0.0.1:8000/agents?agent=rogue_eval_agent")
    pg.wait_for_selector("#agent:not(.hidden)")
    pg.click("#propose")
    pg.wait_for_selector("#step2:not(.hidden)", timeout=120000)
    pg.wait_for_timeout(800)
    pg.locator("#step2").screenshot(path=OUT + "agents_draft.png")
    print("saved agents_draft.png")
    pg.click("#run")
    pg.wait_for_selector("#step3:not(.hidden)", timeout=120000)
    pg.wait_for_timeout(800)
    pg.evaluate("document.getElementById('step3').scrollIntoView()")
    pg.wait_for_timeout(300)
    pg.screenshot(path=OUT + "agents_run.png")
    print("saved agents_run.png")
    b.close()
