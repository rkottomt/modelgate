"""Dynamic analysis: import the auto_map modules inside a sandbox and record behavior."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .fetch import CodeBundle

IMAGE = os.environ.get("MODELGATE_IMAGE", "modelgate-sandbox:latest")
# Total wall-clock budget incl. container start + torch/transformers import (~10s under strace).
TIMEOUT = int(os.environ.get("MODELGATE_SANDBOX_TIMEOUT", "45"))
PKG_NAME = "mg_remote"
RUNNER = Path(__file__).with_name("sandbox_runner.py")
CANARIES = {
    "HF_TOKEN": "hf_MODELGATEcanary000000000000000000",
    "HUGGING_FACE_HUB_TOKEN": "hf_MODELGATEcanary000000000000000000",
    "AWS_ACCESS_KEY_ID": "AKIAMODELGATECANARY0",
    "AWS_SECRET_ACCESS_KEY": "MODELGATE/canary/secret/0000000000000000",
    "OPENAI_API_KEY": "sk-MODELGATE-canary",
}


@dataclass
class SandboxResult:
    mode: str                 # docker | subprocess | skipped
    isolated: bool
    status: str               # ok | timeout | crash | missing_dependency | skipped | error
    exit_code: int | None
    duration: float
    events: list[dict] = field(default_factory=list)
    strace: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def docker_available() -> bool:
    if os.environ.get("MODELGATE_NO_DOCKER") == "1" or not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=10)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _prepare(bundle: CodeBundle, work: Path) -> Path:
    """Copy remote code into work/pkg/mg_remote/ as a package (like HF_MODULES_CACHE does)."""
    pkg = work / "pkg" / PKG_NAME
    pkg.mkdir(parents=True)
    for rel in bundle.files:
        if rel.endswith(".py"):
            dst = pkg / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bundle.root / rel, dst)
    init = pkg / "__init__.py"
    if not init.exists():
        init.write_text("")
    shutil.copy2(RUNNER, work / "runner.py")
    out = work / "out"
    out.mkdir()
    os.chmod(out, 0o777)
    return out


STRACE_RE = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s*(\d+\.\d+)?\s*(\w+)\((.*)\)\s*=\s*(-?\d+|\?)")


def parse_strace(text: str, t0: float | None = None) -> list[dict]:
    """Parse `strace -f -ttt` output. Events before t0 (runner setup / library preload) are dropped."""
    events, first_exec = [], True
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*)$", line)
        if not m:
            continue
        pid, ts, call, rest = m.groups()
        ts = float(ts)
        if t0 is None:
            t0 = ts
        if ts < t0:
            continue
        rec = None
        if call == "execve":
            if first_exec:
                first_exec = False
                continue
            rec = ("process.execve", "execve " + rest.split(",")[0])
        elif call in ("clone", "clone3", "fork", "vfork"):
            continue  # Python threads also clone; execve is the signal we care about
        elif call == "connect" and ("AF_INET" in rest):
            addr = re.search(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"', rest)
            port = re.search(r"htons\((\d+)\)", rest)
            host = (addr.group(1) or addr.group(2)) if addr else "?"
            rec = ("net.connect", f"connect to {host}:{port.group(1) if port else '?'}")
        elif call == "memfd_create":
            rec = ("memfd_create", "memfd_create " + rest.split(",")[0])
        elif call in ("openat", "open"):
            p = re.search(r'"([^"]+)"', rest)
            path = p.group(1) if p else ""
            if re.search(r"\.ssh|\.aws|/etc/passwd|/etc/shadow|cron|/proc/self/environ|\.netrc", path):
                rec = ("file.open", f"open {path}")
        if rec:
            events.append({"t": round(ts - t0, 4), "event": rec[0], "detail": rec[1], "pid": int(pid),
                           "source": "strace", "file": None, "line": None})
    return events


def _read_events(out: Path) -> list[dict]:
    events = []
    log = out / "events.jsonl"
    if log.exists():
        for line in log.read_text(errors="replace").splitlines():
            try:
                e = json.loads(line)
                e.setdefault("source", "audit")
                events.append(e)
            except json.JSONDecodeError:
                continue
    return events


def run(bundle: CodeBundle, force_mode: str | None = None) -> SandboxResult:
    modules = bundle.local_modules
    if not modules:
        return SandboxResult("skipped", True, "skipped", None, 0.0, note="no local auto_map modules to execute")

    use_docker = force_mode == "docker" or (force_mode is None and docker_available())
    work = Path(tempfile.mkdtemp(prefix="modelgate_sbx_"))
    try:
        out = _prepare(bundle, work)
        return _run_docker(work, out, modules) if use_docker else _run_subprocess(work, out, modules)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _status(code: int | None, timed_out: bool) -> str:
    if timed_out:
        return "timeout"
    return {0: "ok", 2: "missing_dependency"}.get(code, "crash")


def _run_docker(work: Path, out: Path, modules: list[str]) -> SandboxResult:
    name = f"modelgate-{os.getpid()}-{int(time.time() * 1000)}"
    env_args = []
    for k, v in {**CANARIES, "HOME": "/tmp/home", "MG_SANDBOX": "1", "PYTHONDONTWRITEBYTECODE": "1",
                 "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}.items():
        env_args += ["-e", f"{k}={v}"]
    base = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,exec,size=64m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "512m", "--cpus", "1",
            "-v", f"{work / 'pkg'}:/work/pkg:ro", "-v", f"{work / 'runner.py'}:/work/runner.py:ro",
            "-v", f"{out}:/out:rw", *env_args, IMAGE]
    py = ["python", "-I", "-B", "/work/runner.py", "/out/events.jsonl", "/work/pkg", PKG_NAME, *modules]
    strace_cmd = ["strace", "-f", "-qq", "-ttt", "--seccomp-bpf", "-o", "/out/strace.log",
                  "-e", "trace=connect,sendto,execve,execveat,memfd_create,openat,open", *py]

    t0 = time.time()
    timed_out, code, used_strace = False, None, True
    try:
        r = subprocess.run(base + strace_cmd, capture_output=True, text=True, timeout=TIMEOUT)
        code = r.returncode
        if code not in (0, 2, 3) and "ptrace" in (r.stderr or "") and not (out / "events.jsonl").exists():
            used_strace = False  # strace not permitted here; rerun plain
            r = subprocess.run(base + py, capture_output=True, text=True, timeout=TIMEOUT)
            code = r.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(["docker", "kill", name], capture_output=True)
    dur = time.time() - t0

    events = _read_events(out)
    strace_log = out / "strace.log"
    if used_strace and strace_log.exists():
        start = next((e.get("ts") for e in events if e["event"] == "sandbox.start"), None)
        events += parse_strace(strace_log.read_text(errors="replace"), t0=start)
    events.sort(key=lambda e: e.get("t", 0))
    return SandboxResult("docker", True, _status(code, timed_out), code, round(dur, 2), events,
                         strace=used_strace and strace_log.exists(),
                         note=f"docker image {IMAGE}: --network none --read-only --cap-drop ALL --pids-limit 64 --memory 512m")


def _run_subprocess(work: Path, out: Path, modules: list[str]) -> SandboxResult:
    home = work / "home_modelgate"
    home.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "MG_SANDBOX": "1", "MG_DENY": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
           "TMPDIR": str(work), **CANARIES}
    cmd = [sys.executable, "-I", "-B", str(work / "runner.py"), str(out / "events.jsonl"), str(work / "pkg"), PKG_NAME, *modules]
    t0 = time.time()
    timed_out, code = False, None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, env=env, cwd=str(work))
        code = r.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
    dur = time.time() - t0
    events = _read_events(out)
    return SandboxResult("subprocess", False, _status(code, timed_out), code, round(dur, 2), events,
                         note="NOT ISOLATED: Docker unavailable; ran in a plain subprocess with temp HOME, scrubbed env, "
                              "and an audit hook that denies network/process operations. Audit hooks can be bypassed.")
