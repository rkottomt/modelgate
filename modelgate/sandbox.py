"""Dynamic analysis: run the repo's code inside a locked-down container and record behavior.

- Files go into the container as a tar stream on stdin (no bind mounts), after symlink/realpath checks.
- docker run --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges
  --user 65534 --pids-limit 256 --memory 1g
- strace (outside the Python process) is ground truth; the Python audit hook is telemetry for file:line.
- No Docker => the code is NOT executed and the verdict is BLOCK ("not isolated"), unless
  MODELGATE_ALLOW_UNISOLATED=1 opts into a best-effort subprocess run.
"""
from __future__ import annotations

import io
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .fetch import CodeBundle

IMAGE = os.environ.get("MODELGATE_IMAGE", "modelgate-sandbox:latest")
# Total wall-clock budget incl. container start + torch/transformers import (~5-10s).
TIMEOUT = int(os.environ.get("MODELGATE_SANDBOX_TIMEOUT", "60"))
PKG_NAME = "mg_remote"
RUNNER = Path(__file__).with_name("sandbox_runner.py")
HOSTNAME = "gpu-node-07"
SANDBOX_HOME = "/home/mlops"
EVENTS_BEGIN, EVENTS_END = "===MG_EVENTS_BEGIN===", "===MG_EVENTS_END==="


@dataclass
class SandboxResult:
    mode: str                 # docker | subprocess | none | skipped
    isolated: bool
    status: str               # ok | timeout | crash | missing_dependency | skipped | not_isolated | error
    exit_code: int | None
    duration: float
    events: list[dict] = field(default_factory=list)
    strace: bool = False
    note: str = ""
    canaries: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("canaries", None)   # canary values never leave this module (or reach the LLM)
        return d


def make_canaries() -> dict[str, str]:
    """Fresh, realistically formatted fake credentials for every scan."""
    alnum = string.ascii_letters + string.digits
    up = string.ascii_uppercase + string.digits
    rnd = lambda chars, n: "".join(secrets.choice(chars) for _ in range(n))  # noqa: E731
    hf = "hf_" + rnd(string.ascii_letters, 34)
    return {
        "HF_TOKEN": hf,
        "HUGGING_FACE_HUB_TOKEN": hf,
        "AWS_ACCESS_KEY_ID": "AKIA" + rnd(up, 16),
        "AWS_SECRET_ACCESS_KEY": rnd(alnum + "/+", 40),
        "OPENAI_API_KEY": "sk-proj-" + rnd(alnum, 48),
    }


def docker_available() -> bool:
    if os.environ.get("MODELGATE_NO_DOCKER") == "1" or not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=10)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _spec(bundle: CodeBundle, modules: list[str]) -> dict:
    refs = [{"kind": e.kind, "key": e.key, "module": e.module, "class_name": e.class_name}
            for e in bundle.auto_map if e.other_repo is None and e.module in modules]
    return {"modules": modules, "refs": refs, "fake_gpu": True}


def _safe_members(bundle: CodeBundle):
    """(arcname, real path) for every scanned file, re-checking symlinks and containment."""
    root = os.path.realpath(bundle.root)
    for rel in sorted(bundle.files):
        if rel.startswith("/") or ".." in rel.split("/"):
            raise ValueError(f"unsafe path {rel!r}")
        full = os.path.join(root, rel)
        if os.path.islink(full) or os.path.commonpath([root, os.path.realpath(full)]) != root:
            raise ValueError(f"symlink or path escape: {rel!r}")
        yield rel, full


def build_tar(bundle: CodeBundle, spec: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add_bytes(name: str, data: bytes, mode: int = 0o644):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime = len(data), mode, int(time.time())
            tar.addfile(ti, io.BytesIO(data))

        add_bytes("runner.py", RUNNER.read_bytes())
        add_bytes("spec.json", json.dumps(spec).encode())
        has_init = False
        for rel, full in _safe_members(bundle):
            with open(full, "rb") as f:
                add_bytes(f"pkg/{PKG_NAME}/{rel}", f.read())
            has_init |= rel == "__init__.py"
        if not has_init:
            add_bytes(f"pkg/{PKG_NAME}/__init__.py", b"")
    return buf.getvalue()


# --- strace parsing -------------------------------------------------------------
LINE_RE = re.compile(r"^(?:\[pid\s+)?(?:(\d+)\]?\s+)?(\d{9,}\.\d+)\s+(\w+)\((.*)$")  # pid is omitted while single-process


def parse_strace(text: str, t0: float | None = None, canaries: dict | None = None) -> list[dict]:
    """Parse `strace -f -ttt` output into timeline events. Lines before t0 (setup/preload) are dropped."""
    events, first_exec = [], True
    canary_vals = [v for v in (canaries or {}).values() if v]
    for raw in text.splitlines():
        m = LINE_RE.match(raw.strip())
        if not m:
            continue
        pid, ts, call, rest = m.groups()
        pid = pid or 0
        ts = float(ts)
        if call == "execve" and first_exec:
            first_exec = False   # the runner itself
            continue
        if t0 is None:
            t0 = ts
        if ts < t0:
            continue
        rec = None
        if call in ("execve", "execveat"):
            target = rest.split(",")[0]
            fileless = "/proc/self/fd" in target or "/dev/fd" in target
            rec = ("process.execve", f"execve {target}" + ("  [fileless: exec from memfd]" if fileless else ""))
        elif call == "connect" and "AF_INET" in rest:
            addr = re.search(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"', rest)
            port = re.search(r"htons\((\d+)\)", rest)
            host = (addr.group(1) or addr.group(2)) if addr else "?"
            rec = ("net.connect", f"connect to {host}:{port.group(1) if port else '?'}")
        elif call == "memfd_create":
            rec = ("memfd_create", "memfd_create " + rest.split(",")[0])
        elif call == "prctl" and "PR_SET_NAME" in rest:
            rec = ("prctl.set_name", "prctl(PR_SET_NAME) " + rest[:80])
        elif call in ("openat", "open"):
            p = re.search(r'"([^"]+)"', rest)
            path = p.group(1) if p else ""
            if re.search(r"\.ssh|\.aws|/etc/passwd|/etc/shadow|cron|/proc/self/environ|\.netrc|/\.dockerenv", path):
                rec = ("file.open", f"open {path}")
        if canary_vals and call in ("sendto", "sendmsg", "connect") and any(v[:12] in rest for v in canary_vals):
            events.append({"t": round(ts - t0, 4), "event": "canary.exfil", "detail": f"{call}() carried a canary credential",
                           "pid": int(pid), "source": "strace", "file": None, "line": None})
        if rec:
            events.append({"t": round(ts - t0, 4), "event": rec[0], "detail": rec[1], "pid": int(pid),
                           "source": "strace", "file": None, "line": None})
    return events


def _parse_events(text: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        try:
            e = json.loads(line)
            if isinstance(e, dict) and "event" in e:
                e["source"] = "audit"
                e["t"] = float(e.get("t", 0))
                events.append(e)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
    return events


def run(bundle: CodeBundle, force_mode: str | None = None) -> SandboxResult:
    modules = bundle.local_modules
    if not modules:
        return SandboxResult("skipped", True, "skipped", None, 0.0, note="no local remote-code modules to execute")
    try:
        spec = _spec(bundle, modules)
        tar = build_tar(bundle, spec)
    except (ValueError, OSError) as e:
        return SandboxResult("none", True, "error", None, 0.0, note=f"refused to stage files: {e}")

    use_docker = force_mode == "docker" or (force_mode is None and docker_available())
    if use_docker:
        return _run_docker(tar)
    if force_mode == "subprocess" or os.environ.get("MODELGATE_ALLOW_UNISOLATED") == "1":
        return _run_subprocess(tar)
    return SandboxResult("none", False, "not_isolated", None, 0.0,
                         note="Docker (with image modelgate-sandbox) is unavailable, so the code was NOT executed. "
                              "Set MODELGATE_ALLOW_UNISOLATED=1 to run a best-effort, non-isolated analysis.")


def run_agent(bundle: CodeBundle, entry: str, force_mode: str | None = None) -> SandboxResult:
    """Run an AI agent's entry script (e.g. agent.py) inside the same hardened sandbox (modelgate run)."""
    if entry not in bundle.files or not entry.endswith(".py"):
        return SandboxResult("none", True, "error", None, 0.0, note=f"entry script {entry!r} not found in the agent folder")
    try:
        tar = build_tar(bundle, {"agent": entry, "modules": [], "refs": [], "fake_gpu": False})
    except (ValueError, OSError) as e:
        return SandboxResult("none", True, "error", None, 0.0, note=f"refused to stage files: {e}")
    if force_mode == "docker" or (force_mode is None and docker_available()):
        return _run_docker(tar)
    if force_mode == "subprocess" or os.environ.get("MODELGATE_ALLOW_UNISOLATED") == "1":
        return _run_subprocess(tar)
    return SandboxResult("none", False, "not_isolated", None, 0.0,
                         note="Docker (with image modelgate-sandbox) is unavailable, so the agent was NOT run.")


def _status(code: int | None, timed_out: bool) -> str:
    if timed_out:
        return "timeout"
    return {0: "ok", 2: "missing_dependency"}.get(code, "crash")


def _run_docker(tar: bytes) -> SandboxResult:
    canaries = make_canaries()
    name = f"modelgate-{os.getpid()}-{secrets.token_hex(4)}"
    env = {**canaries, "HOME": SANDBOX_HOME, "USER": "mlops", "LOGNAME": "mlops", "MG_SANDBOX": "1",
           "CUDA_VISIBLE_DEVICES": "0", "PYTHONDONTWRITEBYTECODE": "1", "HF_HUB_OFFLINE": "1",
           "TRANSFORMERS_OFFLINE": "1", "TOKENIZERS_PARALLELISM": "false", "OMP_NUM_THREADS": "1"}
    env_args = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
    trace = "trace=%network,%process,memfd_create,prctl,openat"
    script = (
        "set -e; mkdir -p /tmp/w && tar -xf - -C /tmp/w; set +e; "
        f"strace -f -qq -ttt -s 128 --seccomp-bpf -e {trace} python -I -B /tmp/w/runner.py /tmp/w; rc=$?; "
        f"echo '{EVENTS_BEGIN}'; cat /tmp/w/events.jsonl 2>/dev/null; echo '{EVENTS_END}'; exit $rc"
    )
    cmd = ["docker", "run", "-i", "--rm", "--name", name, "--hostname", HOSTNAME,
           "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,exec,size=256m",
           "--tmpfs", f"{SANDBOX_HOME}:rw,size=16m,uid=65534,gid=65534,mode=700",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
           "--pids-limit", "256", "--memory", "1g", "--cpus", "2", *env_args, IMAGE, "sh", "-c", script]
    t0 = time.time()
    timed_out, code, out, err = False, None, "", ""
    try:
        r = subprocess.run(cmd, input=tar, capture_output=True, timeout=TIMEOUT)
        code, out, err = r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        timed_out = True
        out = (e.stdout or b"").decode("utf-8", "replace")
        err = (e.stderr or b"").decode("utf-8", "replace")
        subprocess.run(["docker", "kill", name], capture_output=True)
    dur = time.time() - t0

    body = out.split(EVENTS_BEGIN, 1)[1].split(EVENTS_END, 1)[0] if EVENTS_BEGIN in out else ""
    events = _parse_events(body)
    start = next((e.get("ts") for e in events if e["event"] == "sandbox.start"), None)
    events += parse_strace(err, t0=start, canaries=canaries)
    events.sort(key=lambda e: e.get("t", 0))
    has_strace = any(LINE_RE.match(line.strip()) for line in err.splitlines())
    note = (f"{IMAGE}: --network none --read-only --cap-drop ALL --no-new-privileges --user 65534 "
            f"--pids-limit 256 --memory 1g; files via stdin tar (no mounts); strace ground truth")
    if code not in (0, 2, 3) and not events:
        note += f" | container error: {err.strip().splitlines()[-1][:200] if err.strip() else 'unknown'}"
    return SandboxResult("docker", True, _status(code, timed_out), code, round(dur, 2), events, strace=has_strace,
                         note=note, canaries=canaries)


def _run_subprocess(tar: bytes) -> SandboxResult:
    canaries = make_canaries()
    work = Path(tempfile.mkdtemp(prefix="modelgate_sbx_"))
    try:
        with tarfile.open(fileobj=io.BytesIO(tar)) as tf:
            tf.extractall(work / "w", filter="data")
        home = work / "home_modelgate"
        home.mkdir()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "USER": "mlops", "MG_SANDBOX": "1", "MG_DENY": "1",
               "CUDA_VISIBLE_DEVICES": "0", "PYTHONDONTWRITEBYTECODE": "1", "HF_HUB_OFFLINE": "1",
               "TRANSFORMERS_OFFLINE": "1", "TMPDIR": str(work), **canaries}
        cmd = [sys.executable, "-I", "-B", str(work / "w" / "runner.py"), str(work / "w")]
        t0 = time.time()
        timed_out, code = False, None
        try:
            code = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT, env=env, cwd=str(work)).returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        dur = time.time() - t0
        log = work / "w" / "events.jsonl"
        events = _parse_events(log.read_text(errors="replace")) if log.exists() else []
        return SandboxResult("subprocess", False, _status(code, timed_out), code, round(dur, 2), events,
                             note="NOT ISOLATED (MODELGATE_ALLOW_UNISOLATED=1): plain subprocess with temp HOME, scrubbed env, "
                                  "and an audit hook that denies network/process calls. Audit hooks can be bypassed.",
                             canaries=canaries)
    finally:
        shutil.rmtree(work, ignore_errors=True)
