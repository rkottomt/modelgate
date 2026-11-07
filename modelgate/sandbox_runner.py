"""ModelGate sandbox runner. Standalone: must not import modelgate.

Usage: python -I sandbox_runner.py <log.jsonl> <pkg_parent> <pkg_name> <module> [<module> ...]

Installs a PEP 578 audit hook that logs security-relevant events as JSON lines,
then imports each auto_map module the same way trust_remote_code would.
In MG_DENY=1 mode (no-Docker fallback) dangerous operations are also refused.
"""
import json
import os
import sys
import sysconfig
import time

LOG_PATH, PKG_PARENT, PKG_NAME, *MODULES = sys.argv[1:]
DENY = os.environ.get("MG_DENY") == "1"
CANARY_ENV = {"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "OPENAI_API_KEY"}

# --- decoy HOME (only ever inside a throwaway sandbox HOME) ---------------------
HOME = os.environ.get("HOME", "")
if os.environ.get("MG_SANDBOX") == "1" and ("modelgate" in HOME or HOME.startswith("/tmp")):
    os.makedirs(os.path.join(HOME, ".ssh"), exist_ok=True)
    with open(os.path.join(HOME, ".ssh", "id_rsa"), "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nMODELGATE-DECOY-NOT-A-REAL-KEY\n-----END OPENSSH PRIVATE KEY-----\n")
    os.makedirs(os.path.join(HOME, ".aws"), exist_ok=True)
    with open(os.path.join(HOME, ".aws", "credentials"), "w") as f:
        f.write("[default]\naws_secret_access_key = MODELGATE-CANARY\n")

PKG_DIR = os.path.realpath(os.path.join(PKG_PARENT, PKG_NAME))
PKG_DIRS = (PKG_DIR, os.path.abspath(os.path.join(PKG_PARENT, PKG_NAME)))
_log = open(LOG_PATH, "a", buffering=1)
_T0 = time.time()
_in_hook = False

IGNORE_PREFIXES = tuple({os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)} | {"/proc/self", "/dev/urandom"})


STDLIB = os.path.realpath(sysconfig.get_paths()["stdlib"])


def _where():
    """Attribute an event: walk outward past runner/stdlib frames to the first 'real' caller.

    Returns (file, line) relative to the remote package, or (None, None) with the
    library path stored in _where.lib when a third-party library caused it.
    """
    _where.lib = None
    f = sys._getframe(2)
    while f is not None:
        fn = f.f_code.co_filename
        if fn.startswith(PKG_DIRS):
            return os.path.relpath(os.path.realpath(fn), PKG_DIR), f.f_lineno
        if fn == "<string>":
            f = f.f_back  # exec()'d code: blame whoever called exec
            continue
        if fn == __file__ or fn.startswith("<frozen") or (fn.startswith(STDLIB) and "site-packages" not in fn):
            f = f.f_back
            continue
        _where.lib = fn
        return None, None
    return None, None


ALWAYS_LOG = {"socket.connect", "socket.getaddrinfo", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
              "os.spawn", "os.fork", "os.forkpty", "pty.spawn", "os.memfd_create", "open"}


def emit(event, detail, **extra):
    file, line = _where()
    if file is None and event not in ALWAYS_LOG and not event.startswith(("sandbox.", "module.")):
        return  # caused by a trusted library (torch/transformers), not the remote code
    rec = {"t": round(time.time() - _T0, 4), "ts": time.time(), "event": event, "detail": detail, "file": file, "line": line}
    if file is None and getattr(_where, "lib", None):
        rec["caller"] = _where.lib
    rec.update(extra)
    _log.write(json.dumps(rec, default=str) + "\n")


DENY_EVENTS = {"socket.connect", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
               "os.fork", "os.forkpty", "pty.spawn", "socket.getaddrinfo", "os.kill", "ctypes.dlopen"}


def _open_interesting(path, mode):
    if not isinstance(path, str):
        return False
    rp = os.path.realpath(path) if not path.startswith("/proc") else path
    if rp.startswith(PKG_DIRS):
        return any(c in str(mode) for c in "wax+")  # reading own code is normal
    if rp.startswith(IGNORE_PREFIXES) or "__pycache__" in rp:
        return False
    if rp.endswith((".py", ".pyc", ".so", ".pth")) and "site-packages" in rp:
        return False
    return True


def hook(event, args):
    global _in_hook
    if _in_hook:
        return
    _in_hook = True
    try:
        if event == "open":
            path, mode = args[0], args[1]
            if _open_interesting(path, mode):
                emit("open", f"{path} (mode={mode})", path=str(path), mode=str(mode))
        elif event == "socket.connect":
            emit(event, f"connect to {args[1]}", address=str(args[1]))
        elif event == "socket.getaddrinfo":
            emit(event, f"resolve {args[0]}:{args[1]}", host=str(args[0]))
        elif event == "subprocess.Popen":
            emit(event, f"spawn {args[0]} {list(args[1]) if args[1] else ''}", executable=str(args[0]))
        elif event in ("os.system",):
            emit(event, f"shell: {args[0]!r}")
        elif event in ("os.exec", "os.posix_spawn", "os.spawn"):
            emit(event, f"exec {args[0]} {args[1] if len(args) > 1 else ''}")
        elif event in ("os.fork", "os.forkpty", "pty.spawn", "os.kill"):
            emit(event, event)
        elif event == "ctypes.dlopen":
            emit(event, f"dlopen {args[0]}")
        elif event == "exec":
            code = args[0]
            fn = getattr(code, "co_filename", "")
            if fn in ("<string>", "<stdin>") or not (fn.startswith("/") or fn.startswith("<frozen")):
                emit(event, f"exec of dynamically built code ({fn})")
        elif event == "compile":
            fn = args[1] if len(args) > 1 else ""
            if isinstance(fn, str) and fn in ("<string>", "<unknown>") and args[0] is not None:
                src = args[0]
                if isinstance(src, (bytes, bytearray)):
                    src = src.decode("utf-8", "replace")
                emit(event, f"compile dynamic code: {str(src)[:80]!r}")
        elif event == "import":
            name = args[0]
            if name.split(".")[0] in ("socket", "subprocess", "pty", "ctypes", "requests", "httpx", "urllib3", "paramiko"):
                emit(event, f"import {name}")
        if DENY and event in DENY_EVENTS:
            raise PermissionError(f"ModelGate sandbox denied {event}")
    finally:
        _in_hook = False


# memfd_create has no audit event: wrap it.
if hasattr(os, "memfd_create"):
    _orig_memfd = os.memfd_create

    def _memfd_create(name, *a, **k):
        emit("os.memfd_create", f"memfd_create({name!r})")
        if DENY:
            raise PermissionError("ModelGate sandbox denied memfd_create")
        return _orig_memfd(name, *a, **k)

    os.memfd_create = _memfd_create


# env canary access: wrap os.environ
class _WatchedEnviron(type(os.environ)):
    def __getitem__(self, key):
        if key in CANARY_ENV:
            emit("env.read", f"read canary env var {key}", key=key)
        return super().__getitem__(key)


_env = os.environ
os.environ = _WatchedEnviron(_env._data, _env.encodekey, _env.decodekey, _env.encodevalue, _env.decodevalue)

# Preload what trust_remote_code would already have loaded (transformers, torch) so the
# timeline only shows what the remote code itself does.
for _m in ("torch", "transformers", "transformers.modeling_utils", "transformers.configuration_utils"):
    try:
        __import__(_m)
    except Exception:  # noqa: BLE001
        pass

sys.path.insert(0, PKG_PARENT)
_T0 = time.time()
sys.addaudithook(hook)
emit("sandbox.start", f"importing {', '.join(MODULES)}")

import importlib  # noqa: E402
import traceback  # noqa: E402

status = 0
for mod in MODULES:
    try:
        importlib.import_module(f"{PKG_NAME}.{mod}")
        emit("module.imported", f"imported {mod}")
    except ModuleNotFoundError as e:
        missing = (e.name or "").split(".")[0]
        if missing == PKG_NAME:
            emit("module.error", f"{mod}: {e}", error="ModuleNotFoundError")
            status = 3
        else:
            emit("module.missing_dependency", f"{mod}: missing dependency {e.name}", missing=e.name)
            status = max(status, 2)
    except BaseException as e:  # noqa: BLE001
        tb = traceback.extract_tb(e.__traceback__)
        last = next((fr for fr in reversed(tb) if fr.filename.startswith(PKG_DIRS)), None)
        emit("module.error", f"{mod}: {type(e).__name__}: {e}"[:300], error=type(e).__name__,
             err_file=os.path.relpath(os.path.realpath(last.filename), PKG_DIR) if last else None, err_line=last.lineno if last else None)
        status = 3
emit("sandbox.end", f"done (status {status})")
_log.flush()
os._exit(status)
