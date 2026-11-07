# slides/

Hackathon slide materials for ModelGate.

| File | What it is |
|---|---|
| `SLIDES.md` | Speaker notes, timings, sources and judge Q&A for the 7-slide, 5-minute talk, with sources to verify |
| `images/dashboard_allow.png` | Dashboard, `fixtures/clean_model`: green ALLOW (1440x900 @2x, light theme) |
| `images/dashboard_block.png` | Dashboard, `fixtures/sneaky_model`: red BLOCK with file:line reasons and the AI summary |
| `images/dashboard_injection.png` | Dashboard, `fixtures/injection_model`: BLOCK, with a reason line saying the prompt injection has no effect |
| `images/findings_code_context.png` | Crop: first two finding cards (combo + static + sandbox) with code context |
| `images/timeline.png` | Crop: "What the code did when run". Kernel (strace) and Python (audit hook) events |
| `images/terminal_import_hook.png` | Real output of `examples/demo_load.py fixtures/sneaky_model` (LLM off). Findings and the AI panel are trimmed, and the trims are labelled in the image |
| `images/architecture.svg` / `.png` | Hand-written pipeline diagram; the LLM is drawn as a dashed side branch |
| `images/eval.png` | Eval summary and table drawn from `../eval_results.json` |
| `deck/index.html` | **The slideshow.** Open it in a browser: arrow keys or click to move, F for fullscreen. 7 slides, about 4:40. Slide 5 plays `docs/modelgate_demo.mp4` |
| `tools/` | Scripts that regenerate the images (`tools/build/` holds intermediate files) |

## Regenerate

`PY` must be a Python with Playwright and a cached Chromium. The dashboard must already be running at http://127.0.0.1:8000 (`modelgate serve`). The scripts only make GET requests.

```bash
cd /Users/rohitkottomtharayil/modelgate
PY=/path/to/python-with-playwright

# dashboard screenshots + the two crops (waits for #result and the AI summary, up to 90 s)
$PY slides/tools/screenshots.py

# terminal image: capture the real output first, then render it
COLUMNS=130 MODELGATE_LLM=off .venv/bin/python examples/demo_load.py fixtures/sneaky_model \
  > slides/tools/build/demo_out.txt 2>&1
$PY slides/tools/terminal.py

# architecture PNG from the SVG
$PY slides/tools/svg2png.py "$PWD/slides/images/architecture.svg" "$PWD/slides/images/architecture.png" 1510 600


# eval graphic from eval_results.json (the "Why" notes are hard-coded in the script, taken from README)
$PY slides/tools/eval_graphic.py
```
