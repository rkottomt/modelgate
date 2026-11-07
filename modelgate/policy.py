"""Deterministic verdict + allowlist. The LLM never touches anything in this module."""
from __future__ import annotations

import json
import os
import re
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


def _bf(rule, sev, e, msg) -> Finding:
    return Finding(rule, sev, e.get("file") or "(runtime)", e.get("line") or 0, e.get("detail", "")[:200], msg, source="sandbox")


def sandbox_findings(sb: SandboxResult) -> list[Finding]:
    out: list[Finding] = []
    audit_cats: set[str] = set()

    for e in sb.events:
        ev, src = e["event"], e.get("source", "audit")
        cat = rule = None
        if ev in NET_EVENTS:
            cat, rule, sev, msg = "net", "SBX-NET", "critical", f"attempted outbound network: {e['detail']}"
        elif ev in PROC_EVENTS:
            cat, rule, sev, msg = "proc", "SBX-PROC", "critical", f"spawned a process: {e['detail']}"
        elif ev in ("os.memfd_create", "memfd_create"):
            cat, rule, sev, msg = "memfd", "SBX-MEMFD", "critical", "created an in-memory file (fileless-execution pattern)"
        elif ev == "env.read":
            cat, rule, sev, msg = "canary", "SBX-CANARY", "critical", f"touched canary credential {e.get('key', '')}"
        elif ev in ("open", "file.open"):
            path = e.get("path") or e["detail"]
            mode = e.get("mode", "r")
            if SENSITIVE_RE.search(path):
                cat, rule, sev, msg = "sens", "SBX-SENSITIVE", "critical", f"accessed sensitive path (decoy) {path}"
            elif any(c in mode for c in "wax+") and not path.startswith(("/tmp", "/out", "/dev/null")):
                cat, rule, sev, msg = "write", "SBX-WRITE", "high", f"wrote outside cache: {path}"
            else:
                continue
        elif ev in ("exec", "compile") and e.get("file"):
            cat, rule, sev, msg = "dyn", "SBX-DYNEXEC", "high", f"executed dynamically built code: {e['detail']}"
        elif ev == "ctypes.dlopen" and e.get("file"):
            cat, rule, sev, msg = "native", "SBX-NATIVE", "high", f"loaded native library: {e['detail']}"
        else:
            continue
        if src == "strace":
            if cat in audit_cats:
                continue  # already seen by the audit hook
            msg += " [seen by strace but NOT by the audit hook: possible hook bypass]"
        else:
            audit_cats.add(cat)
        out.append(_bf(rule, sev, e, msg))

    # strace events may precede the audit event in the sorted timeline; drop those duplicates
    out = [f for f in out if not ("possible hook bypass" in f.message and _cat(f.rule_id) in audit_cats)]

    if sb.status == "timeout":
        out.append(Finding("SBX-TIMEOUT", "critical", "(runtime)", 0, "", "sandbox timed out (fail closed)", "sandbox"))
    elif sb.status == "crash":
        err = next((e for e in sb.events if e["event"] == "module.error"), {})
        out.append(Finding("SBX-CRASH", "critical", err.get("err_file") or "(runtime)", err.get("err_line") or 0,
                           err.get("detail", "")[:200], "importing the remote code crashed (fail closed)", "sandbox"))
    elif sb.status == "missing_dependency":
        miss = next((e for e in sb.events if e["event"] == "module.missing_dependency"), {})
        out.append(Finding("SBX-INCOMPLETE", "medium", "(runtime)", 0, miss.get("detail", "")[:200],
                           "dynamic analysis incomplete: a dependency is missing from the sandbox image", "sandbox"))
    if sb.mode == "subprocess":
        out.append(Finding("SBX-NOT-ISOLATED", "low", "(runtime)", 0, "", sb.note, "sandbox"))
    return out


def _cat(rule: str) -> str:
    return {"SBX-NET": "net", "SBX-PROC": "proc", "SBX-MEMFD": "memfd", "SBX-CANARY": "canary",
            "SBX-SENSITIVE": "sens", "SBX-WRITE": "write", "SBX-DYNEXEC": "dyn", "SBX-NATIVE": "native"}.get(rule, "")


def decide(findings: list[Finding]) -> tuple[str, list[str]]:
    """BLOCK on any critical (incl. network/process/sensitive/canary/memfd/timeout/crash), WARN on high/medium."""
    crit = [f for f in findings if f.severity == "critical"]
    mid = [f for f in findings if f.severity in ("high", "medium")]
    if crit:
        return BLOCK, [f"{f.rule_id} {f.file}:{f.line} {f.message}" for f in crit]
    if mid:
        return WARN, [f"{f.rule_id} {f.file}:{f.line} {f.message}" for f in mid]
    return ALLOW, ["no high, medium, or critical findings"]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.source != "sandbox", f.file, f.line))


# --- allowlist --------------------------------------------------------------------

def _home() -> Path:
    return Path(os.environ.get("MODELGATE_HOME", Path.home() / ".modelgate"))


def allowlist_path() -> Path:
    return _home() / "allowlist.json"


def load_allowlist() -> list[dict]:
    try:
        return json.loads(allowlist_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def is_allowlisted(repo: str, revision: str | None, code_hash: str) -> bool:
    return any(e.get("repo") == repo and e.get("revision") == (revision or "main") and e.get("code_hash") == code_hash
               for e in load_allowlist())


def add_to_allowlist(repo: str, revision: str | None, code_hash: str, verdict: str) -> None:
    entries = [e for e in load_allowlist() if not (e.get("repo") == repo and e.get("revision") == (revision or "main"))]
    entries.append({"repo": repo, "revision": revision or "main", "code_hash": code_hash,
                    "verdict_at_approval": verdict, "approved_at": time.strftime("%Y-%m-%dT%H:%M:%S")})
    p = allowlist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2))
