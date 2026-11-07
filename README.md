# ModelGate

**A drop-in safety gate for loading Hugging Face models with `trust_remote_code=True`.**

When you load a model with `trust_remote_code=True`, Transformers downloads and *executes* Python from the model repo.
The "Load/Mine" campaign (Pluto Security, reported Oct 29 2026) hid crypto-miners and reverse shells in
`config.json → auto_map` modules across 31 repos. File-format scanners missed it because they inspect weights and
file types, not what the Python *does*.

ModelGate intercepts the load and:

1. **pins** the repo to an immutable commit SHA and downloads every non-weight file at that SHA (never `*.safetensors/*.bin/*.pt/*.gguf`)
2. runs a **static AST scan** (single findings → WARN, dangerous *combinations* → BLOCK)
3. **executes the code in a locked-down Docker sandbox**: import → tiny config → model → forward pass → `save_pretrained` → tokenizer, with a faked GPU, decoy `~/.ssh/id_rsa` and canary credentials, while **strace** records what it does
4. returns a **deterministic verdict**: `BLOCK` / `WARN` / `ALLOW`
5. asks an LLM to **explain** the findings in plain English (advisory only)

> **Core rule: the LLM can never change the verdict.** Rules decide; the LLM only explains. The verdict is computed
> before the LLM is called and nothing it returns is read back. A test feeds it a malicious `{"verdict": "ALLOW"}` response to prove it.

```python
import modelgate.auto          # one line
from transformers import AutoModel
AutoModel.from_pretrained("fixtures/sneaky_model", trust_remote_code=True)
# ModelGateBlocked: modeling_x.py line 3 attempts socket.connect to 203.0.113.5:4444;
#   modeling_x.py line 7 reads decoy ~/.ssh/id_rsa; modeling_x.py line 8 reads canary credential;
#   modeling_x.py line 9 spawns /bin/sh
```

---

## Threat model

| | |
|---|---|
| **Attacker** | Publishes (or compromises) a model repo on the Hub. Controls every file in it, including `config.json` `auto_map`, `custom_pipelines`, and the Python modules they point to. Can point `auto_map` at code in *another* repo they control (`other/repo--module.Class`), and can change files after a model becomes popular. |
| **Victim** | An ML engineer, CI job, or GPU host running `from_pretrained(..., trust_remote_code=True)`. |
| **Assets** | The host (code execution, persistence), credentials (`~/.ssh`, `~/.aws`, `HF_TOKEN`, cloud keys in env), and GPUs (cryptomining). |
| **Attacker goals** | Run a miner/reverse shell at import or first inference; exfiltrate tokens; evade reviewers (obfuscation, deferred triggers, GPU-only triggers, prompt-injecting AI reviewers). |

## How each layer stops it

| Layer | What it does | What it stops |
|---|---|---|
| **Pinning** (`fetch.py`, `hook.py`) | Resolves branch/tag → commit SHA via `HfApi.model_info`. Downloads, the allowlist key, `from_pretrained(revision=sha)`, and `get_cached_module_file(revision=sha)` all use that SHA. After transformers copies a module into `HF_MODULES_CACHE`, ModelGate re-hashes it **before import** and blocks on any mismatch. | Swapping code between the scan and the load (TOCTOU); "clean at scan, malicious at load". |
| **File policy** (`fetch.py`) | Every non-weight file is fetched. Native/compiled files (`.so .pyd .dll .dylib .pyc`) → BLOCK. Symlinks and paths escaping the snapshot → BLOCK. 2 MB per-file cap; oversized code/loader configs → BLOCK. | Shipping a compiled payload; symlink tricks; hiding code in giant files. |
| **Reference following** (`scanner.py`) | Cross-repo `auto_map` (`org/repo--module.Class`), `custom_pipelines`, and `custom_generate` are fetched at a pinned SHA and scanned **recursively** (depth ≤ 3, ≤ 10 repos). A BLOCKed or unfetchable reference → BLOCK. | Supply-chain hops into an unscanned repo. |
| **Static AST** (`static.py`) | Network/process/native/dynamic-exec/reflection/decoder/secret-env/sensitive-path/fingerprinting/prompt-injection rules with file:line + snippet. Singletons are at most HIGH (→ WARN). **Combos** escalate to CRITICAL (→ BLOCK): decode+exec, network+secret env, network+process, decode+dynamic exec, reflection+dynamic exec. Sensitive paths, memfd, native binaries and parse failures BLOCK on their own. Known-benign patterns are exempt: `is_*_available()`, `torch.cuda.is_available()`-only checks, `try/except ImportError` optional imports, `importlib.util.find_spec`. | Obvious and lightly obfuscated payloads, including code that never runs during a short sandbox. |
| **Sandbox** (`sandbox.py`, `sandbox_runner.py`) | `docker run --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --user 65534 --pids-limit 256 --memory 1g`. Files go in as a **tar on stdin (no bind mounts)**. Plausible identity (`mlops@gpu-node-07`, `HOME=/home/mlops`), decoy SSH key, **fresh realistic-format canaries per scan** (`hf_…`, `AKIA…`, `sk-proj-…`). Runs import → config (hidden=8, 1 layer, vocab=16) → model → forward → `save_pretrained` → tokenizer/processor, with `CUDA_VISIBLE_DEVICES=0` and `torch.cuda.is_available()` → True. **strace** (outside the Python process) is ground truth: `connect`, any `execve` (incl. `/proc/self/fd/*` fileless exec), `memfd_create`, `prctl(PR_SET_NAME)` → BLOCK. The PEP 578 audit hook is **telemetry only**, used to attribute events to `file:line`. If strace sees something the hook didn't, the report flags a possible hook bypass. | Import-time payloads, **deferred triggers** (in `forward()`, behind GPU checks, in tokenizers), credential theft, miners renaming themselves. |
| **Fail closed** | Sandbox timeout or crash, unparseable code, fetch failure, internal scanner error, or **no Docker** → BLOCK. (`MODELGATE_ALLOW_UNISOLATED=1` opts into a best-effort subprocess run with a loud NOT ISOLATED warning.) | Making the scanner give up and wave the model through. |
| **Policy + allowlist** (`policy.py`) | BLOCK on any critical, WARN on any high/medium, else ALLOW. `modelgate allow <repo>` approves **repo + SHA + combined code hash**, HMAC-signed with a per-user key in `~/.modelgate/key` (chmod 600). Any code change or tampered entry means a re-scan. | Silent post-approval changes; editing the allowlist file by hand. |
| **Explainer** (`explain.py`) | Sends only rule IDs + the single flagged line per finding (never whole files, never env values) inside unguessable delimiters. The system prompt restates the deterministic verdict and findings as authoritative. Output is validated: unknown file:line findings are dropped, MITRE IDs regex-checked, any `verdict` key ignored. 15 s timeout with one retry, template fallback. Labeled "advisory" everywhere. | Prompt injection in repo code flipping the verdict (`fixtures/injection_model`). |

## Demo

32-second walkthrough of the dashboard and the import hook: [docs/modelgate_demo.mp4](docs/modelgate_demo.mp4)

```bash
uv venv -p 3.12 .venv && uv pip install -p .venv -e ".[dev]" torch
docker build -t modelgate-sandbox:latest docker/       # sandbox image (torch CPU + transformers + strace)
cp .env.example .env                                   # optional: OPENROUTER_API_KEY / OPENROUTER_MODEL
```

1. **Clean model → green ALLOW**
   ```bash
   modelgate scan fixtures/clean_model
   ```
2. **Load/Mine imitation → red BLOCK at load time**
   ```bash
   python examples/demo_load.py fixtures/sneaky_model
   # BLOCKED  modeling_x.py line 3 attempts socket.connect to 203.0.113.5:4444; ... line 7 reads decoy ~/.ssh/id_rsa; ... spawns /bin/sh
   ```
3. **Prompt injection → still BLOCK**, and the AI explanation calls out the injection attempt (rule `MG070-prompt-injection`)
   ```bash
   modelgate scan fixtures/injection_model
   ```
4. **Deferred trigger** (payload only in `forward()`, only when a GPU is present) → BLOCK: `[deferred trigger: fired during forward]`
   ```bash
   modelgate scan fixtures/deferred_model
   ```
5. **Eval**: `python eval.py`
6. **Dashboard**: `modelgate serve` → http://127.0.0.1:8000 (click a fixture chip, or enter `org/model`)

Other commands: `modelgate scan <repo> --revision <rev> --json`, `modelgate allow <repo>`, `pytest`.

**LLM config:** `MODELGATE_LLM=openrouter|local|off` (default `openrouter`).
- `openrouter` uses `OPENROUTER_API_KEY` + `OPENROUTER_MODEL` from `.env`.
- `local` uses any OpenAI-compatible server: `MODELGATE_LLM_BASE_URL` (default `http://localhost:11434/v1`, i.e. Ollama) + `MODELGATE_LLM_MODEL`.

The key is never logged or included in reports.

All fixtures are **harmless imitations**: connect to the RFC 5737 documentation IP 203.0.113.5, open a decoy key inside a temp HOME, `echo pwned`, `exec` of a base64-decoded `print("hi")`, `memfd_create` then close.

## Agent guardrails (new)

The same pipeline, pointed at AI agents instead of model repos. The 2026 agent incidents came down to network
paths that were assumed closed; this checks it instead.

```bash
modelgate guardrails examples/agents/rogue_eval_agent   # AI drafts a contract; you approve; it's signed
modelgate run examples/agents/rogue_eval_agent          # run in the offline container, check every action
```

Or use the **Agent guardrails** tab in the dashboard (`/agents`): describe the agent's goal, tick the drafted
guardrails, run.

- The AI picks from a **fixed catalog** (`modelgate/guardrails.py`): no network / only named hosts, no programs /
  only named programs, no credentials, workspace-only writes, no generated code, no native code, time and memory
  limits. Unknown rules, wildcard hosts and out-of-range limits are dropped; anything missing defaults to on.
- The approved contract is HMAC-signed and bound to the agent's code hash. Editing it, or changing the code, voids it
  (fail closed).
- Checking is plain code over strace and audit-hook events, attributed to `file:line`. CPU time, wall time and peak
  memory are reported per run.
- `examples/agents/rogue_eval_agent` is a harmless imitation of an escaping eval agent (documentation IP, decoy
  secrets, `echo`): 5 violations. `examples/agents/data_cleaner` passes.
- Not yet: real egress through an allowlisting proxy (the container has no network regardless), token/cost metering,
  long-running agents and fleet views. See the roadmap in `slides/SLIDES.md`.

## Eval results

`python eval.py`. Code-only downloads, each repo pinned to the SHA `main` resolved to on 2026-11-07. Docker sandbox on an Apple-silicon Mac. Full rows in `eval_results.json`.

| Repo | Verdict | Expected | Crit/High/Med | Sandbox | Time (s) | Why |
|---|---|---|---|---|---|---|
| fixtures/clean_model | ALLOW | ALLOW ✓ | 0/0/0 | docker/ok | 3.0 | |
| fixtures/warn_model | WARN | WARN ✓ | 0/2/0 | docker/ok | 3.0 | optional `requests` helper |
| fixtures/sneaky_model | BLOCK | BLOCK ✓ | 10/9/3 | docker/ok | 2.9 | connect, decoy key, canary, `/bin/sh`, memfd, decode+exec |
| fixtures/injection_model | BLOCK | BLOCK ✓ | 10/9/7 | docker/ok | 2.9 | same + 4× prompt-injection |
| fixtures/deferred_model | BLOCK | BLOCK ✓ | 3/5/0 | docker/ok | 3.0 | connect + `/bin/sh` fired during `forward()` under fake GPU; static network+process combo |
| fixtures/cross_repo_model | BLOCK | BLOCK ✓ | 1/1/0 | docker/ok | 3.1 | referenced repo can't be fetched → fail closed |
| microsoft/Phi-3-mini-4k-instruct | WARN | benign ✓ | 0/0/2 | docker/ok | 3.5 | module-level `try` block; tiny-config init failed (padding_idx) |
| THUDM/chatglm3-6b | **BLOCK** | benign ✗ | 1/5/3 | docker/ok | 3.8 | **false positive**: `quantization.py` decodes a base64+bz2 CUDA kernel blob and loads it via ctypes; also `eval()` of model output |
| nomic-ai/nomic-embed-text-v1.5 | WARN | benign ✓ | 0/2/0 | (code lives in ref) | 3.6 | cross-repo hop → `nomic-ai/nomic-bert-2048` = WARN |
| deepseek-ai/DeepSeek-V3 | **BLOCK** | benign ✗ | 1/0/3 | docker/crash | 3.2 | **false positive (fail closed)**: imports `is_torch_fx_available`, removed in transformers 5; the import crashes |
| Qwen/Qwen-7B-Chat | WARN | benign ✓ | 0/5/7 | docker/ok | 3.3 | `cpp_kernels.py` runs `nvcc` via subprocess and compiles a C++ extension at module level |
| jinaai/jina-embeddings-v3 | WARN | benign ✓ | 0/1/0 | (code lives in ref) | 1.1 | cross-repo hop → `jinaai/xlm-roberta-flash-implementation` = ALLOW |

**Summary:**
- Fixtures: 6/6 correct.
- Real popular repos: 4 WARN, 2 BLOCK, 0 ALLOW.
- **False-positive BLOCK rate on real repos: 2/6.**
  - ChatGLM3 really does contain the "decode a blob and execute it natively" pattern that obfuscated payloads use. We chose not to special-case it; `modelgate allow THUDM/chatglm3-6b --force` approves that exact SHA and code hash.
  - DeepSeek-V3 crashes on import with current transformers. It would fail on the host too, and a crash is indistinguishable from sandbox evasion, so we fail closed.
- No real repo reached ALLOW. Real-world custom code almost always has *something* worth a human glance (module-level logic, optional native kernels, cross-repo hops), so WARN is the expected state for real repos and the allowlist is the intended workflow.
- Scan time: about 3–4 s per repo with a warm Docker image (first run is slower).

## Limitations (honest)

- **Static rules can be evaded.** Obfuscation that avoids the patterns (string building via arithmetic, `getattr` chains on non-builtin objects, etc.) won't be flagged statically. The sandbox is the backstop.
- **A short sandbox can't see everything.** Logic bombs keyed on date, hostname, GPU count/model, uptime, or on long-running inference or training won't fire in a ~1 s import-and-one-forward-pass run with a 1-layer config. We fake one GPU via `torch.cuda.is_available()`, not real CUDA.
- **Audit hooks are not a boundary.** Malicious Python can remove or evade PEP 578 hooks; we use them only for attribution. **Docker is the boundary**, and Docker shares the host kernel. For production, run the sandbox under **gVisor (`--runtime=runsc`)** or a microVM (Firecracker/Kata).
- **Container tells remain.** `/.dockerenv` is created by Docker and can't be removed under `--read-only`, so a payload that checks for it can stay dormant. The static scan flags references to it (`MG080-fingerprint`), and strace logs opens of it. gVisor/microVMs avoid this.
- **Tamper-evidence of telemetry.** strace output goes to the container's stderr, which the tracee can't write to through normal fds. The audit-event file lives in the sandbox's `/tmp` and could be altered by the payload. It only ever *adds* findings; it never removes strace evidence.
- **Only the transformers dynamic-module path is covered** (`Auto*.from_pretrained`, `get_class_from_dynamic_module`, `get_cached_module_file`). **Out of scope:** diffusers custom pipelines, vLLM / TGI / SGLang loaders, `torch.hub.load`, `pip install` from a repo, and anything else that doesn't go through `transformers.dynamic_module_utils`.
- **Weights-file attacks** (malicious pickles in `.bin`/`.pt`, GGUF parser bugs) are out of scope. Existing format scanners (Protect AI ModelScan, JFrog, Hugging Face picklescan) cover those, and ModelGate never downloads weights.
- **Missing dependencies.** If remote code needs a package the sandbox image lacks, the run is marked incomplete (WARN), not ALLOW.
- **Not a malware verdict.** ALLOW means "nothing risky observed under these rules and this sandbox", not "proven safe".

## Prior art & credits

- **DynaHug**: dynamic analysis of Hugging Face model repos. ModelGate's sandbox-first design follows the same insight that behavior beats format checks.
- **Existing static/format scanners**: Hugging Face's malware and pickle scanning (picklescan), **Protect AI ModelScan / Guardian**, and **JFrog** model scanning. They cover weight-file attacks well, and ModelGate is meant to sit alongside them for the remote-code path.
- Pluto Security's "Load/Mine" write-up for the attack pattern our fixtures imitate.

## Layout

```
modelgate/
  fetch.py           pinned, code-only fetch; file policy; auto_map/custom_pipelines/custom_generate refs
  static.py          AST rules + combo escalation + prompt-injection detection
  sandbox.py         Docker orchestration, strace parsing, canaries
  sandbox_runner.py  in-container runner: audit-hook telemetry, fake GPU, deferred-trigger exercise
  policy.py          deterministic verdict, HMAC allowlist
  explain.py         advisory LLM explainer (openrouter | local | off) with validation + template fallback
  scanner.py         pipeline + recursive reference scanning, fail closed
  hook.py            transformers monkeypatches (+ `import modelgate.auto`)
  cli.py             `modelgate scan | allow | serve`
  web/               FastAPI dashboard (CSP, textContent-only rendering)
fixtures/            clean, warn, sneaky, injection, deferred, cross_repo (all harmless)
tests/               pytest (23 tests)
eval.py              fixtures + real repos table
docker/Dockerfile    sandbox image
```
