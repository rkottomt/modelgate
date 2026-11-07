import sys
from playwright.sync_api import sync_playwright
src, out, w, h = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": w, "height": h}, device_scale_factor=2)
    pg.goto("file://" + src); pg.wait_for_timeout(200)
    pg.screenshot(path=out, clip={"x":0,"y":0,"width":w,"height":h})
    b.close()
