"""ModelGate sandbox runner. Standalone: must not import modelgate.

Usage: python -I -B sandbox_runner.py <workdir>
  <workdir>/pkg/mg_remote/   remote repo files (code + configs + tokenizer files, no weights)
  <workdir>/spec.json        {"modules": [...], "refs": [{kind,key,module,class_name}], "fake_gpu": true}
  <workdir>/events.jsonl     output (telemetry)

Phases (what trust_remote_code + normal use would trigger):
  import auto_map modules -> build a tiny config -> instantiate model -> forward pass
  -> save_pretrained -> instantiate tokenizer/processor classes.
The PEP 578 audit hook is TELEMETRY ONLY (attribution to file:line). The boundary is the
container; ground truth is strace, which runs outside this process.
"""
import json
import os
import sys
import sysconfig
import time

WORK = os.path.realpath(sys.argv[1])
PKG_NAME = "mg_remote"
PKG_PARENT = os.path.join(WORK, "pkg")
PKG_DIR = os.path.realpath(os.path.join(PKG_PARENT, PKG_NAME))
PKG_DIRS = (PKG_DIR, os.path.abspath(os.path.join(PKG_PARENT, PKG_NAME)))
SPEC = json.load(open(os.path.join(WORK, "spec.json")))
DENY = os.environ.get("MG_DENY") == "1"
CANARY_ENV = {"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "OPENAI_API_KEY"}
TINY = {
    "hidden_size": 8, "d_model": 8, "n_embd": 8, "dim": 8, "embed_dim": 8,
    "num_hidden_layers": 1, "num_layers": 1, "n_layer": 1, "n_layers": 1,
    "vocab_size": 16, "padded_vocab_size": 16,
    "num_attention_heads": 2, "n_head": 2, "n_heads": 2, "num_heads": 2,
    "num_key_value_heads": 2, "multi_query_group_num": 2, "kv_channels": 4, "head_dim": 4,
    "intermediate_size": 16, "ffn_hidden_size": 16, "ffn_dim": 16, "n_inner": 16, "moe_intermediate_size": 16,
    "max_position_embeddings": 64, "n_positions": 64, "seq_length": 64,
    "n_routed_experts": 2, "num_experts": 2, "num_local_experts": 2, "num_experts_per_tok": 1, "n_shared_experts": 1,
    "first_k_dense_replace": 0, "q_lora_rank": None, "kv_lora_rank": 4, "qk_rope_head_dim": 2,
    "qk_nope_head_dim": 2, "v_head_dim": 4, "topk_group": 1, "n_group": 1,
}
DROP_KEYS = {"auto_map", "architectures", "_name_or_path", "transformers_version", "torch_dtype", "dtype",
             "quantization_config", "_attn_implementation", "attn_implementation", "custom_pipelines"}

# --- keep the runner's own stdio away from the remote code (strace owns the container's stderr) ---
_devnull = os.open(os.devnull, os.O_RDWR)
os.dup2(_devnull, 0)
os.dup2(_devnull, 1)
if os.environ.get("MG_KEEP_STDERR") != "1":
    os.dup2(_devnull, 2)

# --- decoy HOME, only inside a throwaway sandbox HOME ---
HOME = os.environ.get("HOME", "")
if os.environ.get("MG_SANDBOX") == "1" and (HOME == "/home/mlops" or "modelgate" in HOME):
    os.makedirs(os.path.join(HOME, ".ssh"), exist_ok=True)
    with open(os.path.join(HOME, ".ssh", "id_rsa"), "w") as f:
        f.write(os.environ.get("MG_DECOY_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n"))
    os.makedirs(os.path.join(HOME, ".aws"), exist_ok=True)
    with open(os.path.join(HOME, ".aws", "credentials"), "w") as f:
        f.write(f"[default]\naws_access_key_id = {os.environ.get('AWS_ACCESS_KEY_ID', '')}\n"
                f"aws_secret_access_key = {os.environ.get('AWS_SECRET_ACCESS_KEY', '')}\n")
os.environ.pop("MG_DECOY_KEY", None)

_log = open(os.path.join(WORK, "events.jsonl"), "a", buffering=1)
_T0 = time.time()
_in_hook = False
STDLIB = os.path.realpath(sysconfig.get_paths()["stdlib"])
IGNORE_PREFIXES = tuple({os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)} | {"/dev/urandom"})
PHASE = "setup"


def _where():
    """Walk outward past runner/stdlib frames to the first 'real' caller."""
    _where.lib = None
    f = sys._getframe(2)
    while f is not None:
        fn = f.f_code.co_filename
        if fn.startswith(PKG_DIRS):
            return os.path.relpath(os.path.realpath(fn), PKG_DIR), f.f_lineno
        if fn == "<string>" or fn == __file__ or fn.startswith("<frozen") or (fn.startswith(STDLIB) and "site-packages" not in fn):
            f = f.f_back
            continue
        _where.lib = fn
        return None, None
    return None, None


ALWAYS_LOG = {"socket.connect", "socket.getaddrinfo", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
              "os.spawn", "os.fork", "os.forkpty", "pty.spawn", "os.memfd_create", "open"}


def emit(event, detail, **extra):
    file, line = _where()
    if file is None and event not in ALWAYS_LOG and not event.startswith(("sandbox.", "module.", "phase.", "exercise.")):
        return  # caused by a trusted library (torch/transformers), not the remote code
    rec = {"t": round(time.time() - _T0, 4), "ts": time.time(), "event": event, "detail": detail,
           "file": file, "line": line, "phase": PHASE}
    if file is None and getattr(_where, "lib", None):
        rec["caller"] = _where.lib
    rec.update(extra)
    _log.write(json.dumps(rec, default=str) + "\n")


DENY_EVENTS = {"socket.connect", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
               "os.fork", "os.forkpty", "pty.spawn", "socket.getaddrinfo", "os.kill", "ctypes.dlopen"}
SAVE_DIR = os.path.realpath(os.path.join(WORK, "saved"))


def _open_interesting(path, mode):
    if not isinstance(path, str):
        return False
    rp = os.path.realpath(path) if not path.startswith("/proc") else path
    if rp.startswith(SAVE_DIR):
        return False  # our own save_pretrained target
    if rp.startswith(PKG_DIRS):
        return any(c in str(mode) for c in "wax+")  # reading own code/config is normal
    if rp.startswith(IGNORE_PREFIXES) or "__pycache__" in rp:
        return False
    return True


def hook(event, args):
    global _in_hook
    if _in_hook:
        return
    _in_hook = True
    try:
        if event == "open":
            if _open_interesting(args[0], args[1]):
                emit("open", f"{args[0]} (mode={args[1]})", path=str(args[0]), mode=str(args[1]))
        elif event == "socket.connect":
            emit(event, f"connect to {args[1]}", address=str(args[1]))
        elif event == "socket.getaddrinfo":
            emit(event, f"resolve {args[0]}:{args[1]}", host=str(args[0]))
        elif event == "subprocess.Popen":
            emit(event, f"spawn {args[0]} {list(args[1]) if args[1] else ''}", executable=str(args[0]))
        elif event == "os.system":
            emit(event, f"shell: {args[0]!r}")
        elif event in ("os.exec", "os.posix_spawn", "os.spawn"):
            emit(event, f"exec {args[0]} {args[1] if len(args) > 1 else ''}")
        elif event in ("os.fork", "os.forkpty", "pty.spawn", "os.kill"):
            emit(event, event)
        elif event == "ctypes.dlopen":
            emit(event, f"dlopen {args[0]}")
        elif event == "exec":
            fn = getattr(args[0], "co_filename", "")
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
            if args[0].split(".")[0] in ("socket", "subprocess", "pty", "ctypes", "requests", "httpx", "urllib3", "paramiko"):
                emit(event, f"import {args[0]}")
        if DENY and event in DENY_EVENTS:
            raise PermissionError(f"ModelGate sandbox denied {event}")
    finally:
        _in_hook = False


if hasattr(os, "memfd_create"):
    _orig_memfd = os.memfd_create

    def _memfd_create(name, *a, **k):
        emit("os.memfd_create", f"memfd_create({name!r})")
        if DENY:
            raise PermissionError("ModelGate sandbox denied memfd_create")
        return _orig_memfd(name, *a, **k)

    os.memfd_create = _memfd_create


class _WatchedEnviron(type(os.environ)):
    def __getitem__(self, key):
        if key in CANARY_ENV:
            emit("env.read", f"read canary env var {key}", key=key)
        return super().__getitem__(key)


_env = os.environ
os.environ = _WatchedEnviron(_env._data, _env.encodekey, _env.decodekey, _env.encodevalue, _env.decodevalue)

# Preload what trust_remote_code would already have loaded.
for _m in ("torch", "transformers", "transformers.modeling_utils", "transformers.configuration_utils",
           "transformers.tokenization_utils", "transformers.tokenization_utils_fast"):
    try:
        __import__(_m)
    except Exception:  # noqa: BLE001
        pass

try:
    import torch  # noqa: E402
except Exception:  # noqa: BLE001
    torch = None

_REAL_CUDA = {}


def fake_gpu(on: bool):
    """Pretend a GPU exists, so GPU-gated payloads fire."""
    if torch is None:
        return
    if not _REAL_CUDA:
        _REAL_CUDA.update(is_available=torch.cuda.is_available, device_count=torch.cuda.device_count)
    if on:
        torch.cuda.is_available = lambda: True
        torch.cuda.device_count = lambda: 1
    else:
        torch.cuda.is_available = _REAL_CUDA["is_available"]
        torch.cuda.device_count = _REAL_CUDA["device_count"]


sys.path.insert(0, PKG_PARENT)
_T0 = time.time()
sys.addaudithook(hook)
emit("sandbox.start", f"modules: {', '.join(SPEC['modules']) or '(none)'}")

import importlib  # noqa: E402
import traceback  # noqa: E402


def _err(e):
    tb = traceback.extract_tb(e.__traceback__)
    last = next((fr for fr in reversed(tb) if fr.filename.startswith(PKG_DIRS)), None)
    return {"error": type(e).__name__, "err_file": os.path.relpath(os.path.realpath(last.filename), PKG_DIR) if last else None,
            "err_line": last.lineno if last else None}


def _purge():
    for name in list(sys.modules):
        if name == PKG_NAME or name.startswith(PKG_NAME + "."):
            del sys.modules[name]


status = 0
loaded = {}
PHASE = "import"
gpu = bool(SPEC.get("fake_gpu", True))
fake_gpu(gpu)
for mod in SPEC["modules"]:
    for attempt in (1, 2):
        try:
            loaded[mod] = importlib.import_module(f"{PKG_NAME}.{mod}")
            emit("module.imported", f"imported {mod}" + (" (fake GPU)" if gpu else ""))
            break
        except BaseException as e:  # noqa: BLE001
            if attempt == 1 and gpu:  # maybe a GPU-only code path: retry as a CPU box
                emit("exercise.note", f"{mod}: import failed under fake GPU ({type(e).__name__}); retrying without", **_err(e))
                _purge()
                loaded.clear()
                fake_gpu(False)
                gpu = False
                continue
            if isinstance(e, ModuleNotFoundError) and (e.name or "").split(".")[0] != PKG_NAME:
                emit("module.missing_dependency", f"{mod}: missing dependency {e.name}", missing=e.name)
                status = max(status, 2)
            else:
                emit("module.error", f"{mod}: {type(e).__name__}: {e}"[:300], **_err(e))
                status = 3
            break

# re-import anything purged by a CPU retry
for mod in SPEC["modules"]:
    if mod not in loaded and status != 3:
        try:
            loaded[mod] = importlib.import_module(f"{PKG_NAME}.{mod}")
        except BaseException:  # noqa: BLE001
            pass


def _cls(ref):
    m = loaded.get(ref["module"])
    return getattr(m, ref["class_name"], None) if m else None


def exercise():
    """Trigger deferred code paths: config -> model -> forward -> save -> tokenizer/processor."""
    global PHASE
    fake_gpu(True)
    refs = SPEC.get("refs", [])
    try:
        raw = json.load(open(os.path.join(PKG_DIR, "config.json")))
    except Exception:  # noqa: BLE001
        raw = {}
    model_refs = [r for r in refs if r["kind"] == "auto_map" and r["key"].startswith("AutoModel")]
    cfg_ref = next((r for r in refs if r["kind"] == "auto_map" and r["key"] == "AutoConfig"), None)

    config = None
    if model_refs or cfg_ref:
        PHASE = "config"
        try:
            cfg_cls = _cls(cfg_ref) if cfg_ref else None
            if cfg_cls is None:
                mc = next((_cls(r) for r in model_refs if _cls(r) is not None), None)
                cfg_cls = getattr(mc, "config_class", None)
            if cfg_cls is not None:
                kwargs = {k: v for k, v in raw.items() if k not in DROP_KEYS}
                for k, v in TINY.items():
                    if k in kwargs or k in ("hidden_size", "num_hidden_layers", "vocab_size"):
                        kwargs[k] = v
                config = cfg_cls(**kwargs)
                for k in ("hidden_size", "num_hidden_layers", "vocab_size"):
                    if hasattr(config, k):
                        setattr(config, k, TINY[k])
                emit("phase.config", f"built tiny {type(config).__name__} (hidden=8, layers=1, vocab=16)")
        except BaseException as e:  # noqa: BLE001
            emit("exercise.error", f"config: {type(e).__name__}: {e}"[:300], **_err(e))

    if config is not None:
        for r in model_refs:
            cls = _cls(r)
            if cls is None:
                continue
            try:
                PHASE = "model_init"
                torch.manual_seed(0)
                model = cls(config)
                model.eval()
                emit("phase.model_init", f"instantiated {cls.__name__}")
                PHASE = "forward"
                ids = torch.randint(0, 16, (1, 4))
                with torch.no_grad():
                    try:
                        model(input_ids=ids)
                    except TypeError:
                        model(ids)
                emit("phase.forward", f"{cls.__name__}: dummy forward pass ok")
                PHASE = "save"
                model.save_pretrained(os.path.join(SAVE_DIR, r["key"]))
                emit("phase.save", f"{cls.__name__}: save_pretrained ok")
            except BaseException as e:  # noqa: BLE001
                emit("exercise.error", f"{r['key']} ({PHASE}): {type(e).__name__}: {e}"[:300], **_err(e))

    for r in refs:
        if r["kind"] != "auto_map" or not any(t in r["key"] for t in ("Tokenizer", "Processor", "FeatureExtractor")):
            continue
        cls = _cls(r)
        if cls is None:
            continue
        PHASE = "tokenizer"
        try:
            cls.from_pretrained(PKG_DIR)
            emit("phase.tokenizer", f"instantiated {cls.__name__}")
        except BaseException as e:  # noqa: BLE001
            emit("exercise.error", f"{r['key']}: {type(e).__name__}: {e}"[:300], **_err(e))


if status != 3 and torch is not None:
    try:
        exercise()
    except BaseException as e:  # noqa: BLE001
        emit("exercise.error", f"{type(e).__name__}: {e}"[:300], **_err(e))
PHASE = "end"
emit("sandbox.end", f"done (status {status})")
_log.flush()
os._exit(status)
