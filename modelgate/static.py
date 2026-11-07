"""Static AST scan of remote code. Deterministic rules only.

Single findings are at most HIGH (=> WARN). Combinations are escalated to CRITICAL (=> BLOCK)
by `combos()`: decode+exec, network+secret env, network+process, sensitive path access,
memfd, native code, unparseable/oversized code (fail closed).
"""
from __future__ import annotations

import ast
import io
import math
import re
import tokenize
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .fetch import MAX_FILE_BYTES, CodeBundle

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    snippet: str
    message: str
    source: str = "static"   # static | sandbox | manifest | combo | reference

    def to_dict(self) -> dict:
        return asdict(self)


# --- rule tables -----------------------------------------------------------

NETWORK_MODULES = ("socket", "requests", "urllib", "urllib3", "httpx", "aiohttp", "http.client", "ftplib", "telnetlib",
                   "paramiko", "huggingface_hub", "websocket", "websockets", "smtplib")
PROCESS_MODULES = ("subprocess", "pty", "multiprocessing")
NATIVE_LOADERS = ("ctypes", "cffi", "torch.utils.cpp_extension")
FINGERPRINT_MODULES = ("datetime", "random", "platform", "getpass", "uuid")

# dotted call prefix -> (rule_id, severity, description)
CALL_RULES: list[tuple[str, str, str, str]] = [
    ("socket.gethostname", "MG080-fingerprint", "medium", "reads the hostname (environment fingerprinting)"),
    ("socket.", "MG011-network", "high", "opens a network socket"),
    ("urllib.request.", "MG011-network", "high", "makes an HTTP request"),
    ("urllib3.", "MG011-network", "high", "makes an HTTP request"),
    ("requests.", "MG011-network", "high", "makes an HTTP request"),
    ("httpx.", "MG011-network", "high", "makes an HTTP request"),
    ("aiohttp.", "MG011-network", "high", "makes an HTTP request"),
    ("http.client.", "MG011-network", "high", "makes an HTTP request"),
    ("huggingface_hub.", "MG011-network", "high", "downloads from the Hub at runtime (unscanned code/data)"),
    ("torch.hub.", "MG011-network", "high", "torch.hub downloads and runs remote code"),
    ("subprocess.", "MG012-process", "high", "spawns a process"),
    ("pty.spawn", "MG012-process", "high", "spawns a pseudo-terminal (reverse-shell pattern)"),
    ("os.system", "MG012-process", "high", "runs a shell command"),
    ("os.popen", "MG012-process", "high", "runs a shell command"),
    ("os.exec", "MG012-process", "high", "replaces the process (os.exec*)"),
    ("os.spawn", "MG012-process", "high", "spawns a process"),
    ("os.posix_spawn", "MG012-process", "high", "spawns a process"),
    ("os.fork", "MG012-process", "high", "forks the process"),
    ("os.memfd_create", "MG013-memfd", "critical", "creates an anonymous in-memory file (fileless execution)"),
    ("ctypes.CDLL", "MG014-native", "high", "loads a native library via ctypes"),
    ("ctypes.cdll.", "MG014-native", "high", "loads a native library via ctypes"),
    ("ctypes.PyDLL", "MG014-native", "high", "loads a native library via ctypes"),
    ("ctypes.pydll.", "MG014-native", "high", "loads a native library via ctypes"),
    ("ctypes.WinDLL", "MG014-native", "high", "loads a native library via ctypes"),
    ("ctypes.windll.", "MG014-native", "high", "loads a native library via ctypes"),
    ("ctypes.CFUNCTYPE", "MG014-native", "high", "builds a native function pointer"),
    ("ctypes.util.find_library", "MG014-native", "high", "locates a native library"),
    ("cffi.", "MG014-native", "high", "loads native code via cffi"),
    ("torch.utils.cpp_extension.", "MG014-native", "high", "compiles/loads a native extension at runtime"),
    ("torch.ops.load_library", "MG014-native", "high", "loads a native shared library"),
    ("marshal.loads", "MG020-dynexec", "high", "deserializes code objects"),
    ("pickle.loads", "MG020-dynexec", "high", "unpickles data (arbitrary code)"),
    ("importlib.util.find_spec", "", "", ""),           # benign availability check
    ("importlib.metadata.", "", "", ""),                # benign version check
    ("importlib.", "MG022-dynimport", "high", "imports/loads modules programmatically"),
    ("__import__", "MG022-dynimport", "high", "uses __import__"),
    ("codecs.decode", "MG024-decode", "high", "decodes data (common obfuscation step)"),
    ("bytes.fromhex", "MG024-decode", "high", "decodes hex data (common obfuscation step)"),
    ("base64.b64decode", "MG024-decode", "high", "base64-decodes data (common obfuscation step)"),
    ("base64.urlsafe_b64decode", "MG024-decode", "high", "base64-decodes data (common obfuscation step)"),
    ("base64.standard_b64decode", "MG024-decode", "high", "base64-decodes data (common obfuscation step)"),
    ("base64.decodebytes", "MG024-decode", "high", "base64-decodes data (common obfuscation step)"),
    ("base64.b32decode", "MG024-decode", "high", "decodes data (common obfuscation step)"),
    ("base64.b85decode", "MG024-decode", "high", "decodes data (common obfuscation step)"),
    ("base64.a85decode", "MG024-decode", "high", "decodes data (common obfuscation step)"),
    ("base64.b16decode", "MG024-decode", "high", "decodes data (common obfuscation step)"),
    ("zlib.decompress", "MG024-decode", "high", "decompresses data (common obfuscation step)"),
    ("lzma.decompress", "MG024-decode", "high", "decompresses data (common obfuscation step)"),
    ("bz2.decompress", "MG024-decode", "high", "decompresses data (common obfuscation step)"),
    ("gzip.decompress", "MG024-decode", "high", "decompresses data (common obfuscation step)"),
    ("binascii.", "MG024-decode", "high", "decodes binary data (common obfuscation step)"),
    ("platform.", "MG080-fingerprint", "medium", "reads platform details (environment fingerprinting)"),
    ("datetime.", "MG080-fingerprint", "medium", "reads the date/time (possible time bomb)"),
    ("time.time", "", "", ""),
    ("random.", "MG080-fingerprint", "medium", "uses randomness (possible probabilistic trigger)"),
    ("getpass.getuser", "MG080-fingerprint", "medium", "reads the username (environment fingerprinting)"),
    ("os.chmod", "MG050-write-outside", "medium", "changes file permissions"),
    ("os.chown", "MG050-write-outside", "medium", "changes file ownership"),
    ("os.symlink", "MG050-write-outside", "medium", "creates a symlink"),
    ("shutil.copy", "MG050-write-outside", "medium", "copies files"),
    ("shutil.move", "MG050-write-outside", "medium", "moves files"),
    ("os.rename", "MG050-write-outside", "medium", "renames files"),
]
DECODERS = ("base64.", "zlib.decompress", "codecs.decode", "bytes.fromhex", "binascii.", "lzma.decompress",
            "gzip.decompress", "bz2.decompress", "marshal.loads")
DYNAMIC_BUILTINS = {"exec", "eval", "compile"}

SENSITIVE_PATH_RE = re.compile(
    r"(\.ssh(/|$)|id_rsa|id_ed25519|\.aws(/|$)|/etc/passwd|/etc/shadow|crontab|/var/spool/cron|"
    r"\.bash_history|\.netrc|\.git-credentials|\.kube/config|\.docker/config\.json|\.huggingface/token|"
    r"\.cache/huggingface/token|/proc/self/environ)"
)
FINGERPRINT_PATH_RE = re.compile(r"^(/proc(/|$)|/sys(/|$)|/\.dockerenv$|/run/\.containerenv$|/etc/hostname$|/etc/machine-id$)")
SENSITIVE_ENV_RE = re.compile(
    r"^(HF_TOKEN|HUGGING_FACE_HUB_TOKEN|HUGGINGFACE_TOKEN|AWS_[A-Z_]+|OPENAI[A-Z_]*|ANTHROPIC[A-Z_]*|"
    r"GITHUB_TOKEN|GH_TOKEN|WANDB_API_KEY|[A-Z0-9_]*_(KEY|SECRET|TOKEN|PASSWORD))$"
)
INJECTION_RE = re.compile(
    r"(ignore (all |any )?(previous|prior|above) instructions|(ai|llm|automated) (reviewer|scanner|analyst|auditor)|"
    r"report (verdict )?(allow|safe)|verdict\W{0,4}allow|you must report|do not (mention|report) (any )?findings|"
    r"this (file|model|code) (has been|is) (audited|verified)|system:\s*ai)", re.I)

# Module-level calls that are idiomatic in HF code and not side effects worth flagging.
SAFE_TOPLEVEL_CALLS = re.compile(
    r"(^|\.)(get_logger|getLogger|TypeVar|namedtuple|NewType|compile|parse|version|"
    r"is_[a-z0-9_]+_available|require_version|dataclass|field|frozenset|set|dict|list|tuple|"
    r"OrderedDict|defaultdict|Enum|partial|lru_cache|register|make_dataclass|ContextVar|"
    r"_LazyModule|_LazyAutoMapping|getattr|object|float|int|str|range|Path|declare|replace_return_docstrings|"
    r"add_start_docstrings|add_code_sample_docstrings|warn|filterwarnings|simplefilter|"
    r"get_torch_version|logging\.[a-z_]+|check_min_version|get_activation|finfo|iinfo|tensor|device|dtype|"
    r"pre_tokenizers\.[A-Za-z]+|normalizers\.[A-Za-z]+|bytes_to_unicode|_import_structure|set_verbosity\w*|"
    r"find_spec|cuda\.is_available|torch\.cuda\.is_available|get_device_capability|"
    r"signature|hasattr|isinstance|issubclass|len|any|all|sorted|split|startswith|endswith|keys|"
    r"is_bf16_supported|device_count|get_device_name|"
    r"ClassInstantier|ACT2CLS|ACT2FN|auto_docstring|deprecate_kwarg|can_return_tuple|use_kernel_forward_from_hub)$"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def dotted_name(node: ast.AST, depth: int = 0) -> str | None:
    if depth > 50:
        return None
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = dotted_name(node.func, depth + 1)
        if inner:
            parts.append(inner + "()")
            return ".".join(reversed(parts))
    return None


def _is_import_error_handler(stmt: ast.Try) -> bool:
    for h in stmt.handlers:
        names = [h.type] if not isinstance(h.type, ast.Tuple) else list(h.type.elts)
        if any(isinstance(n, ast.Name) and n.id in ("ImportError", "ModuleNotFoundError") for n in names):
            return True
    return False


def _is_safe_stmt(stmt: ast.stmt) -> bool:
    """Is a top-level statement free of import-time side effects?"""
    if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Pass)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
        return True
    if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        return stmt.value is None or _is_safe_expr(stmt.value)
    if isinstance(stmt, (ast.If, ast.Try)) or type(stmt).__name__ == "TryStar":
        blocks = [stmt.body, getattr(stmt, "orelse", []), getattr(stmt, "finalbody", [])]
        for h in getattr(stmt, "handlers", []):
            blocks.append(h.body)
        if isinstance(stmt, ast.If) and not _is_safe_expr(stmt.test):
            return False
        return all(_is_safe_stmt(s) for b in blocks for s in b)
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        return _is_safe_expr(stmt.value)
    if isinstance(stmt, (ast.Raise, ast.Assert)):
        return True
    return False


def _is_safe_expr(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func) or ""
            if not SAFE_TOPLEVEL_CALLS.search(name):
                return False
    return True


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]):
        self.rel = rel
        self.lines = lines
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}
        self.func_depth = 0
        self.import_error_depth = 0

    def snippet(self, line: int) -> str:
        return self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""

    def add(self, rule: str, sev: str, node: ast.AST, msg: str) -> None:
        line = getattr(node, "lineno", 0)
        self.findings.append(Finding(rule, sev, self.rel, line, self.snippet(line), msg))

    def at_import_time(self) -> bool:
        return self.func_depth == 0

    def where(self) -> str:
        return " at import time" if self.at_import_time() else ""

    def resolve(self, name: str | None) -> str | None:
        if not name:
            return None
        head, _, rest = name.partition(".")
        if head in self.aliases:
            real = self.aliases[head]
            return f"{real}.{rest}" if rest else real
        return name

    def visit_FunctionDef(self, node):
        self.func_depth += 1
        self.generic_visit(node)
        self.func_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_Try(self, node: ast.Try):
        if _is_import_error_handler(node):
            self.import_error_depth += 1
            for s in node.body:
                self.visit(s)
            self.import_error_depth -= 1
            for part in (node.handlers, node.orelse, node.finalbody):
                for s in part:
                    self.visit(s)
        else:
            self.generic_visit(node)

    def visit_Import(self, node):
        for a in node.names:
            local = a.asname or a.name.split(".")[0]
            self.aliases[local] = a.name if a.asname else a.name.split(".")[0]
            self._check_import(a.name, node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        if node.level:
            for a in node.names:
                self.aliases[a.asname or a.name] = a.name
            return
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}"
            self._check_import(f"{mod}.{a.name}", node, base=mod)

    def _check_import(self, full: str, node, base: str | None = None):
        mod = base or full
        top = mod.split(".")[0]
        # optional imports inside `try: ... except ImportError` are a known-benign pattern
        soft = self.import_error_depth > 0
        if mod.startswith(NETWORK_MODULES) or top in [m.split(".")[0] for m in NETWORK_MODULES if "." not in m]:
            self.add("MG010-net-import", "medium" if soft else "high", node, f"imports network library `{mod}` in model code")
        elif top in PROCESS_MODULES:
            self.add("MG010-proc-import", "medium" if soft else "high", node, f"imports process library `{mod}`")
        elif mod.startswith(NATIVE_LOADERS) or full.startswith("torch.utils.cpp_extension"):
            self.add("MG014-native", "high", node, f"imports native-code loader `{mod}`")
        elif full == "torch.hub" or mod == "torch.hub":
            self.add("MG011-network", "high", node, "imports torch.hub (remote code download)")
        elif top in FINGERPRINT_MODULES:
            self.add("MG080-fingerprint", "medium", node, f"imports `{top}` (environment/time fingerprinting)")
        elif top == "marshal":
            self.add("MG020-dynexec", "high", node, "imports marshal (code object deserialization)")
        if full.endswith(".memfd_create"):
            self.add("MG013-memfd", "critical", node, "imports os.memfd_create")

    def visit_Assign(self, node: ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Subscript) and self.resolve(dotted_name(t.value)) == "sys.modules":
                self.add("MG025-reflection", "high", node, "writes to sys.modules (module hijacking)")
            if isinstance(t, ast.Attribute) and self.resolve(dotted_name(t.value)) in ("builtins", "__builtins__"):
                self.add("MG025-reflection", "high", node, "overwrites a builtin")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        raw = dotted_name(node.func)
        name = self.resolve(raw) or ""
        where = self.where()

        if name and "()" not in name:  # skip methods on call results, e.g. b64decode(x).decode()
            for prefix, rule, sev, desc in CALL_RULES:
                if name == prefix.rstrip(".") or name.startswith(prefix):
                    if rule:
                        self.add(rule, sev, node, f"`{name}()` {desc}{where}")
                    break

        # reflection on builtins / sys.modules
        if name in ("getattr", "setattr", "delattr", "vars") and node.args:
            tgt = node.args[0]
            tname = self.resolve(dotted_name(tgt.value if isinstance(tgt, ast.Subscript) else tgt)) or ""
            if tname in ("builtins", "__builtins__", "sys.modules", "sys") or (isinstance(tgt, ast.Call) and
                                                                               (dotted_name(tgt.func) or "") in ("globals", "vars", "locals")):
                self.add("MG025-reflection", "high", node, f"`{name}()` on {tname or 'globals()'} (reflection to hide calls)")

        # sock.connect(("host", port)) on any object
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("connect", "connect_ex", "sendto") \
                and node.args and isinstance(node.args[0], ast.Tuple):
            host = node.args[0].elts[0] if node.args[0].elts else None
            h = host.value if isinstance(host, ast.Constant) else "<dynamic>"
            self.add("MG011-network", "high", node, f"`{node.func.attr}()` to {h}{where}")

        # exec / eval / compile builtins (bare names only; not re.compile / torch.compile)
        if isinstance(node.func, ast.Name) and node.func.id in DYNAMIC_BUILTINS and node.func.id not in self.aliases:
            inner = [self.resolve(dotted_name(n.func)) or "" for arg in node.args for n in ast.walk(arg) if isinstance(n, ast.Call)]
            if any(n.startswith(DECODERS) for n in inner):
                self.add("MG021-decode-exec", "high", node, f"`{node.func.id}()` runs decoded data (obfuscated payload pattern){where}")
            elif any(n in ("open", "io.open") or n.endswith((".read", ".read_text", ".read_bytes")) for n in inner):
                self.add("MG023-file-exec", "high", node, f"`{node.func.id}()` executes code read from a file{where}")
            else:
                self.add("MG020-dynexec", "high", node, f"`{node.func.id}()` executes dynamically built code{where}")

        # env var reads of secrets
        if name in ("os.getenv", "os.environ.get", "os.environ.pop", "os.environ.setdefault") and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and SENSITIVE_ENV_RE.match(a0.value):
                self.add("MG041-secret-env", "high", node, f"reads secret env var `{a0.value}`{where}")

        # writes outside cache dir
        if name in ("open", "io.open", "builtins.open") and self._is_write_mode(node):
            target = node.args[0] if node.args else None
            if target is not None and self._is_outside_path(target):
                self.add("MG050-write-outside", "high", node, f"writes to a path outside the model cache{where}")
        if name.endswith((".write_text", ".write_bytes")) and isinstance(node.func, ast.Attribute):
            if self._is_outside_path(node.func.value):
                self.add("MG050-write-outside", "high", node, f"writes to a path outside the model cache{where}")

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        name = self.resolve(dotted_name(node.value))
        if name == "os.environ" and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            if SENSITIVE_ENV_RE.match(node.slice.value):
                self.add("MG041-secret-env", "high", node, f"reads secret env var `{node.slice.value}`")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        v = node.value
        if isinstance(v, str):
            if SENSITIVE_PATH_RE.search(v):
                self.add("MG040-sensitive-path", "critical", node, f"references sensitive path `{v[:60]}`")
            elif FINGERPRINT_PATH_RE.match(v):
                self.add("MG080-fingerprint", "medium", node, f"references `{v[:40]}` (sandbox/host fingerprinting)")
            if len(v) >= 120 and sum(c.isspace() for c in v) / len(v) < 0.02 and shannon_entropy(v) >= 5.0:
                self.add("MG030-entropy", "high", node,
                         f"long high-entropy string literal ({len(v)} chars, entropy {shannon_entropy(v):.2f}): possible obfuscated payload")
            if INJECTION_RE.search(v):
                self.add("MG070-prompt-injection", "medium", node, "string addresses an AI reviewer (prompt-injection attempt)")
        elif isinstance(v, bytes) and len(v) >= 120 and shannon_entropy(v.decode("latin-1")) >= 5.0:
            self.add("MG030-entropy", "high", node, f"long high-entropy bytes literal ({len(v)} bytes)")

    @staticmethod
    def _is_write_mode(node: ast.Call) -> bool:
        mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
        return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+")

    def _is_outside_path(self, node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith(("/", "~")):
                if not n.value.startswith(("/tmp", "/dev/null")):
                    return True
            if isinstance(n, ast.Call):
                cn = self.resolve(dotted_name(n.func)) or ""
                if cn.endswith(("expanduser", "Path.home", "home")):
                    return True
        return False


def _comment_injections(src: str, rel: str, lines: list[str]) -> list[Finding]:
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT and INJECTION_RE.search(tok.string):
                ln = tok.start[0]
                out.append(Finding("MG070-prompt-injection", "medium", rel, ln, lines[ln - 1].strip()[:200],
                                   "comment addresses an AI reviewer (prompt-injection attempt)"))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass
    return out


def reachable_modules(bundle: CodeBundle) -> set[str]:
    """.py files transformers would actually import: auto_map modules + their transitive relative imports."""
    todo = [e.module_file for e in bundle.auto_map if e.other_repo is None and e.module_file in bundle.files]
    seen: set[str] = set()
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        seen.add(rel)
        try:
            tree = ast.parse((bundle.root / rel).read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError, RecursionError, OSError):
            continue
        base = Path(rel).parent
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                pkg = base
                for _ in range(node.level - 1):
                    pkg = pkg.parent
                names = [node.module] if node.module else [a.name for a in node.names]
                for n in names:
                    cand = (pkg / (n.replace(".", "/") + ".py")).as_posix().lstrip("./") if str(pkg) != "." else n.replace(".", "/") + ".py"
                    if cand in bundle.files:
                        todo.append(cand)
    return seen


def scan_file(path: Path, rel: str, reachable: bool = True) -> list[Finding]:
    """Scan one file. Any parsing failure is a fail-closed CRITICAL finding."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [Finding("MG003-oversized", "critical", rel, 0, "", f"code file exceeds {MAX_FILE_BYTES} byte cap (fail closed)")]
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src, filename=rel)
        lines = src.splitlines()
        v = _Visitor(rel, lines)
        v.visit(tree)
        findings = v.findings + _comment_injections(src, rel, lines)
        for stmt in (tree.body if reachable else []):  # only files transformers actually imports run at load
            if not _is_safe_stmt(stmt):
                findings.append(Finding("MG002-module-side-effect", "medium", rel, stmt.lineno, v.snippet(stmt.lineno),
                                        "statement runs at import time (outside any def/class)"))
        return findings
    except SyntaxError as e:
        return [Finding("MG001-parse-error", "critical", rel, e.lineno or 0, "", f"could not parse (fail closed): {e.msg}")]
    except (RecursionError, MemoryError, ValueError, OSError) as e:
        return [Finding("MG001-parse-error", "critical", rel, 0, "", f"analysis failed (fail closed): {type(e).__name__}")]


def scan_manifest(bundle: CodeBundle) -> list[Finding]:
    out = []
    for i in bundle.issues:
        rule = {"native": "MG090-native-binary", "symlink": "MG091-symlink", "escape": "MG091-symlink",
                "oversized": "MG003-oversized", "unreadable": "MG001-parse-error"}[i.kind]
        out.append(Finding(rule, "critical", i.path, 0, "", f"{i.detail} (fail closed)", source="manifest"))
    for e in bundle.auto_map:
        if e.other_repo:
            out.append(Finding("MG060-cross-repo", "high", e.source, 0, f'"{e.key}": "{e.reference}"',
                               f"{e.kind} pulls code from ANOTHER repo `{e.other_repo}` (supply-chain hop; scanned recursively)",
                               source="manifest"))
        elif e.module_file not in bundle.files:
            out.append(Finding("MG061-missing-module", "medium", e.source, 0, f'"{e.key}": "{e.reference}"',
                               f"{e.kind} module `{e.module_file}` is not in the repo", source="manifest"))
    return out


COMBO_RULES = [
    # (name, required rule-prefix groups, message)
    ("decode+exec", [("MG021",)], "decoded data is executed (obfuscated payload)"),
    ("network+secret", [("MG011", "MG010-net"), ("MG041",)], "network capability combined with secret env access (exfiltration)"),
    ("network+process", [("MG011", "MG010-net"), ("MG012", "MG010-proc")], "network + process spawning (reverse shell / dropper pattern)"),
    ("decode+dynexec", [("MG024",), ("MG020", "MG022", "MG023")], "decoding combined with dynamic execution"),
    ("reflection+dynexec", [("MG025",), ("MG020", "MG021", "MG023")], "reflection combined with dynamic execution"),
]


def combos(findings: list[Finding]) -> list[Finding]:
    """Escalate dangerous combinations (per repo) to CRITICAL."""
    out = []
    for name, groups, msg in COMBO_RULES:
        hits = []
        for g in groups:
            match = sorted((f for f in findings if f.rule_id.startswith(g) and f.source == "static"),
                           key=lambda f: "import" in f.rule_id)  # prefer the call site over the import line
            if not match:
                break
            hits.append(match[0])
        else:
            first = hits[0]
            where = ", ".join(f"{h.file}:{h.line}" for h in hits)
            out.append(Finding(f"MG100-combo-{name}", "critical", first.file, first.line, first.snippet,
                               f"{msg} [{where}]", source="combo"))
    return out


def scan(bundle: CodeBundle) -> list[Finding]:
    findings = scan_manifest(bundle)
    reach = reachable_modules(bundle)
    for rel in bundle.py_files:
        findings.extend(scan_file(bundle.root / rel, rel, reachable=rel in reach))
    findings.extend(combos(findings))
    seen, uniq = set(), []
    for f in findings:
        key = (f.rule_id, f.file, f.line, f.message)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    specific = {(f.file, f.line) for f in uniq if f.rule_id != "MG002-module-side-effect"}
    uniq = [f for f in uniq if not (f.rule_id == "MG002-module-side-effect" and (f.file, f.line) in specific)]
    return sorted(uniq, key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
