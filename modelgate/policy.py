"""Deterministic verdict + HMAC-protected allowlist. The LLM never touches anything in this module."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path

from .sandbox import SandboxResult
from .static import SEVERITY_ORDER, Finding

BLOCK, WARN, ALLOW = "BLOCK", "WARN", "ALLOW"

SENSITIVE_RE = re.compile(r"(\.ssh/|id_rsa|id_ed25519|\.aws/|/etc/passwd|/etc/shadow|cron|\.netrc|"
                          r"\.git-credentials|\.kube/config|/proc/self/environ|huggingface/token)")
PROC_EVENTS = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
               "os.forkpty", "pty.spawn", "process.execve"}
NET_EVENTS = {"socket.connect", "socket.getaddrinfo", "net.connect"}


def _classify(e: dict):
    """event -> (category, rule, severity, message) or None."""
    ev = e["event"]
    if ev in NET_EVENTS:
        return "net", "SBX-NET", "critical", f"attempted outbound network: {e['detail']}"
    if ev in PROC_EVENTS:
        return "proc", "SBX-PROC", "critical", f"spawned a process: {e['detail']}"
    if ev in ("os.memfd_create", "memfd_create"):
        return "memfd", "SBX-MEMFD", "critical", "created an in-memory file (fileless-execution pattern)"
    if ev == "prctl.set_name":
        return "procname", "SBX-PROCNAME", "critical", "renamed its process via prctl(PR_SET_NAME) (miner/implant disguise)"
    if ev == "canary.exfil":
        return "exfil", "SBX-EXFIL", "critical", "sent a canary credential over a socket"
    if ev == "env.read":
        return "canary", "SBX-CANARY", "critical", f"touched canary credential {e.get('key', '')}"
    if ev in ("open", "file.open"):
        path = e.get("path") or e["detail"]
        mode = e.get("mode", "r")
        if SENSITIVE_RE.search(path):
            return "sens", "SBX-SENSITIVE", "critical", f"accessed sensitive path (decoy) {path.replace('open ', '')}"
        if "/.dockerenv" in path or path.startswith(("/proc/1/", "/sys/")):
            return "fingerprint", "SBX-FINGERPRINT", "medium", f"probed the environment: {path}"
        if any(c in mode for c in "wax+") and not path.startswith(("/tmp", "/dev/null")):
            return "write", "SBX-WRITE", "high", f"wrote outside cache: {path}"
        return None
    if ev in ("exec", "compile") and e.get("file"):
        return "dyn", "SBX-DYNEXEC", "high", f"executed dynamically built code: {e['detail']}"
    if ev == "ctypes.dlopen" and e.get("file"):
        return "native", "SBX-NATIVE", "high", f"loaded native library: {e['detail']}"
    return None


def sandbox_findings(sb: SandboxResult) -> list[Finding]:
    """strace (outside the process) is ground truth; the audit hook supplies file:line attribution.

    The audit hook is telemetry: its events can only ADD findings; their absence proves nothing.
    """
    out: list[Finding] = []
    by_cat: dict[str, dict] = {"strace": {}, "audit": {}}
    for e in sb.events:
        c = _classify(e)
        if c:
            by_cat["strace" if e.get("source") == "strace" else "audit"].setdefault(c[0], (e, c))

    for cat in list(by_cat["strace"]) + [c for c in by_cat["audit"] if c not in by_cat["strace"]]:
        if cat in by_cat["strace"]:
            e, (_, rule, sev, msg) = by_cat["strace"][cat]
            attr = by_cat["audit"].get(cat, (None,))[0]
            file = (attr or {}).get("file") or "(runtime)"
            line = (attr or {}).get("line") or 0
            detail = (attr or e)["detail"]
            if attr is None and sb.mode == "docker":
                msg += " [seen by strace only: audit hook saw nothing (bypass or native code)]"
            phase = (attr or {}).get("phase")
        else:
            e, (_, rule, sev, msg) = by_cat["audit"][cat]
            file, line, detail, phase = e.get("file") or "(runtime)", e.get("line") or 0, e["detail"], e.get("phase")
        if phase and phase not in ("import", "setup"):
            msg += f" [deferred trigger: fired during {phase}]"
        out.append(Finding(rule, sev, file, line, detail[:200], msg, source="sandbox"))

    if sb.status == "timeout":
        out.append(Finding("SBX-TIMEOUT", "critical", "(runtime)", 0, "", "sandbox timed out (fail closed)", "sandbox"))
    elif sb.status == "crash":
        err = next((e for e in sb.events if e["event"] == "module.error"), {})
        out.append(Finding("SBX-CRASH", "critical", err.get("err_file") or "(runtime)", err.get("err_line") or 0,
                           err.get("detail", sb.note)[:200], "importing the remote code crashed (fail closed)", "sandbox"))
    elif sb.status == "missing_dependency":
        miss = next((e for e in sb.events if e["event"] == "module.missing_dependency"), {})
        out.append(Finding("SBX-INCOMPLETE", "medium", "(runtime)", 0, miss.get("detail", "")[:200],
                           "dynamic analysis incomplete: a dependency is missing from the sandbox image", "sandbox"))
    elif sb.status == "not_isolated":
        out.append(Finding("SBX-NOT-ISOLATED", "critical", "(runtime)", 0, "", sb.note, "sandbox"))
    elif sb.status == "error":
        out.append(Finding("SBX-STAGING", "critical", "(runtime)", 0, "", sb.note + " (fail closed)", "sandbox"))
    errs = [e for e in sb.events if e["event"] == "exercise.error"]
    if errs:
        out.append(Finding("SBX-EXERCISE-INCOMPLETE", "medium", errs[0].get("err_file") or "(runtime)", errs[0].get("err_line") or 0,
                           errs[0]["detail"][:200], f"{len(errs)} deferred-trigger step(s) could not run (config/model/forward/tokenizer); "
                           "behavior on those paths is unobserved", "sandbox"))
    if sb.mode == "subprocess":
        out.append(Finding("SBX-UNISOLATED-RUN", "low", "(runtime)", 0, "", sb.note, "sandbox"))
    return out


def decide(findings: list[Finding]) -> tuple[str, list[str]]:
    """BLOCK on any critical, WARN on any high/medium, else ALLOW."""
    crit = [f for f in findings if f.severity == "critical"]
    mid = [f for f in findings if f.severity in ("high", "medium")]
    if crit:
        return BLOCK, [f"{f.rule_id} {f.file}:{f.line} {f.message}" for f in crit]
    if mid:
        return WARN, [f"{f.rule_id} {f.file}:{f.line} {f.message}" for f in mid]
    return ALLOW, ["no high, medium, or critical findings"]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.source != "sandbox", f.file, f.line))


# --- allowlist (HMAC-protected) -----------------------------------------------------

def _home() -> Path:
    return Path(os.environ.get("MODELGATE_HOME", Path.home() / ".modelgate"))


def allowlist_path() -> Path:
    return _home() / "allowlist.json"


def _key() -> bytes:
    p = _home() / "key"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    os.chmod(p, 0o600)
    return p.read_bytes()


def _mac(entry: dict) -> str:
    msg = "\0".join(str(entry.get(k, "")) for k in ("repo", "revision", "code_hash", "verdict_at_approval", "approved_at"))
    return hmac.new(_key(), msg.encode(), hashlib.sha256).hexdigest()


def load_allowlist() -> list[dict]:
    """Only entries with a valid HMAC are returned; tampered entries are ignored."""
    try:
        entries = json.loads(allowlist_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict) and hmac.compare_digest(str(e.get("mac", "")), _mac(e))]


def is_allowlisted(repo: str, revision: str | None, code_hash: str) -> bool:
    return any(e.get("repo") == repo and e.get("revision") == (revision or "local") and e.get("code_hash") == code_hash
               for e in load_allowlist())


def add_to_allowlist(repo: str, revision: str | None, code_hash: str, verdict: str) -> None:
    """`revision` should be the pinned commit SHA (or None for local dirs)."""
    rev = revision or "local"
    entries = [e for e in load_allowlist() if not (e.get("repo") == repo and e.get("revision") == rev)]
    entry = {"repo": repo, "revision": rev, "code_hash": code_hash,
             "verdict_at_approval": verdict, "approved_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    entry["mac"] = _mac(entry)
    entries.append(entry)
    p = allowlist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2))
