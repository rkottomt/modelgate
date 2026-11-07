"""Static AST scan of remote code. Deterministic rules only."""
from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .fetch import CodeBundle

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    snippet: str
    message: str
    source: str = "static"   # static | sandbox | manifest

    def to_dict(self) -> dict:
        return asdict(self)


# --- rule tables -----------------------------------------------------------

DANGEROUS_MODULES = {
    "socket": "network", "subprocess": "process", "pty": "process", "ctypes": "native code",
    "urllib": "network", "urllib.request": "network", "urllib3": "network", "requests": "network",
    "httpx": "network", "http.client": "network", "ftplib": "network", "telnetlib": "network",
    "paramiko": "network", "marshal": "deserialization", "multiprocessing": "process",
}

# dotted call name -> (rule_id, category)
DANGEROUS_CALL_PREFIXES = {
    "socket.": ("MG011-network", "opens a network socket"),
    "urllib.request.": ("MG011-network", "makes an HTTP request"),
    "requests.": ("MG011-network", "makes an HTTP request"),
    "httpx.": ("MG011-network", "makes an HTTP request"),
    "http.client.": ("MG011-network", "makes an HTTP request"),
    "subprocess.": ("MG012-process", "spawns a process"),
    "pty.spawn": ("MG012-process", "spawns a pseudo-terminal (reverse-shell pattern)"),
    "os.system": ("MG012-process", "runs a shell command"),
    "os.popen": ("MG012-process", "runs a shell command"),
    "os.exec": ("MG012-process", "replaces the process (os.exec*)"),
    "os.spawn": ("MG012-process", "spawns a process"),
    "os.posix_spawn": ("MG012-process", "spawns a process"),
    "os.fork": ("MG012-process", "forks the process"),
    "os.memfd_create": ("MG013-memfd", "creates an anonymous in-memory file (fileless execution)"),
    "ctypes.": ("MG014-native", "loads native code via ctypes"),
    "marshal.loads": ("MG020-dynexec", "deserializes code objects"),
    "pickle.loads": ("MG020-dynexec", "unpickles data (arbitrary code)"),
}
SAFE_CALL_NAMES = {"socket.gethostname"}  # harmless lookups

DYNAMIC_BUILTINS = {"exec", "eval", "compile"}
DECODERS = ("base64.", "zlib.decompress", "codecs.decode", "bytes.fromhex", "binascii.", "lzma.decompress",
            "gzip.decompress", "bz2.decompress")

SENSITIVE_PATH_RE = re.compile(
    r"(\.ssh(/|$)|id_rsa|id_ed25519|\.aws(/|$)|/etc/passwd|/etc/shadow|crontab|/var/spool/cron|"
    r"\.bash_history|\.netrc|\.git-credentials|\.kube/config|\.docker/config\.json|\.huggingface/token|"
    r"\.cache/huggingface/token|/proc/self/environ)"
)
SENSITIVE_ENV_RE = re.compile(
    r"^(HF_TOKEN|HUGGING_FACE_HUB_TOKEN|HUGGINGFACE_TOKEN|AWS_[A-Z_]+|OPENAI[A-Z_]*|ANTHROPIC[A-Z_]*|"
    r"GITHUB_TOKEN|GH_TOKEN|WANDB_API_KEY|[A-Z0-9_]*_(KEY|SECRET|TOKEN|PASSWORD))$"
)

# Module-level calls that are idiomatic in HF code and not side effects worth flagging.
SAFE_TOPLEVEL_CALLS = re.compile(
    r"(^|\.)(get_logger|getLogger|TypeVar|namedtuple|NewType|compile|parse|version|"
    r"is_[a-z0-9_]+_available|require_version|dataclass|field|frozenset|set|dict|list|tuple|"
    r"OrderedDict|defaultdict|Enum|partial|lru_cache|register|make_dataclass|ContextVar|"
    r"_LazyModule|_LazyAutoMapping|getattr|object|float|int|str|range|Path|declare|replace_return_docstrings|"
    r"add_start_docstrings|add_code_sample_docstrings|warn|filterwarnings|simplefilter|import_module|"
    r"get_torch_version|logging\.[a-z_]+|check_min_version|get_activation|finfo|iinfo|tensor|device|dtype|"
    r"pre_tokenizers\.[A-Za-z]+|normalizers\.[A-Za-z]+|bytes_to_unicode|_import_structure|set_verbosity\w*)$"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def dotted_name(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):  # e.g. Path.home().joinpath -> "Path.home().joinpath"
        inner = dotted_name(node.func)
        if inner:
            parts.append(inner + "()")
            return ".".join(reversed(parts))
    return None


def _is_safe_stmt(stmt: ast.stmt) -> bool:
    """Is a top-level statement free of import-time side effects?"""
    if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Pass)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
        return True  # docstring / bare constant
    if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        value = stmt.value
        if value is None:
            return True
        return _is_safe_expr(value)
    if isinstance(stmt, (ast.If, ast.Try)) or type(stmt).__name__ == "TryStar":
        blocks = [stmt.body, getattr(stmt, "orelse", []), getattr(stmt, "finalbody", [])]
        for h in getattr(stmt, "handlers", []):
            blocks.append(h.body)
        if isinstance(stmt, ast.If) and not _is_safe_expr(stmt.test):
            return False
        return all(_is_safe_stmt(s) for b in blocks for s in b)
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        return _is_safe_expr(stmt.value)
    if isinstance(stmt, ast.Raise) or isinstance(stmt, ast.Assert):
        return True
    return False


def _is_safe_expr(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func) or ""
            if not SAFE_TOPLEVEL_CALLS.search(name):
                return False
        elif isinstance(node, (ast.Lambda,)):
            continue
    return True


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]):
        self.rel = rel
        self.lines = lines
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}   # local name -> real dotted module/object
        self.depth = 0                       # >0 when inside def/class body
        self.func_depth = 0

    # helpers
    def snippet(self, line: int) -> str:
        return self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""

    def add(self, rule: str, sev: str, node: ast.AST, msg: str) -> None:
        line = getattr(node, "lineno", 0)
        self.findings.append(Finding(rule, sev, self.rel, line, self.snippet(line), msg))

    def at_import_time(self) -> bool:
        return self.func_depth == 0  # module-level or class body runs on import

    def resolve(self, name: str | None) -> str | None:
        if not name:
            return None
        head, _, rest = name.partition(".")
        if head in self.aliases:
            real = self.aliases[head]
            return f"{real}.{rest}" if rest else real
        return name

    # visitors
    def visit_FunctionDef(self, node):
        self.func_depth += 1
        self.generic_visit(node)
        self.func_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_Import(self, node):
        for a in node.names:
            self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            self._check_import(a.name, node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        if node.level:  # relative import: local module
            for a in node.names:
                self.aliases[a.asname or a.name] = a.name
            return
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}"
            self._check_import(f"{mod}.{a.name}", node, base=mod)

    def _check_import(self, full: str, node, base: str | None = None):
        for m in (base, full):
            if m and m in DANGEROUS_MODULES:
                self.add("MG010-import", "medium", node, f"imports `{m}` ({DANGEROUS_MODULES[m]} capability)")
                return
            if m and m.split(".")[0] in ("socket", "subprocess", "pty", "ctypes", "requests", "httpx", "urllib"):
                self.add("MG010-import", "medium", node, f"imports `{m}`")
                return
        if full.endswith(".memfd_create") or full in ("os.system", "os.popen"):
            self.add("MG010-import", "high", node, f"imports `{full}` directly")

    def visit_Call(self, node: ast.Call):
        raw = dotted_name(node.func)
        name = self.resolve(raw) or ""
        imp = self.at_import_time()
        sev_hi = "critical" if imp else "high"
        where = " at import time" if imp else ""

        if name and name not in SAFE_CALL_NAMES:
            for prefix, (rule, desc) in DANGEROUS_CALL_PREFIXES.items():
                if name == prefix.rstrip(".") or name.startswith(prefix):
                    sev = "critical" if rule == "MG013-memfd" else sev_hi
                    self.add(rule, sev, node, f"`{name}()` {desc}{where}")
                    break

        # sock.connect(("host", port)) on any object
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("connect", "connect_ex", "sendto") \
                and node.args and isinstance(node.args[0], ast.Tuple):
            host = node.args[0].elts[0] if node.args[0].elts else None
            h = host.value if isinstance(host, ast.Constant) else "<dynamic>"
            self.add("MG011-network", sev_hi, node, f"`{node.func.attr}()` to {h}{where}")

        # exec / eval / compile builtins (only bare names, not re.compile / torch.compile)
        if isinstance(node.func, ast.Name) and node.func.id in DYNAMIC_BUILTINS and node.func.id not in self.aliases:
            decoded = any(
                isinstance(n, ast.Call) and (self.resolve(dotted_name(n.func)) or "").startswith(DECODERS)
                for arg in node.args for n in ast.walk(arg)
            )
            if decoded:
                self.add("MG021-decode-exec", "critical", node,
                         f"`{node.func.id}()` runs base64/zlib-decoded code (obfuscated payload pattern){where}")
            elif node.args and not isinstance(node.args[0], ast.Constant):
                self.add("MG020-dynexec", sev_hi, node, f"`{node.func.id}()` executes dynamically built code{where}")
            else:
                self.add("MG020-dynexec", "medium", node, f"`{node.func.id}()` on a constant string")

        # __import__ / importlib.import_module with non-constant names
        if name in ("__import__", "importlib.import_module") and node.args and not isinstance(node.args[0], ast.Constant):
            self.add("MG022-dynimport", "high", node, f"`{name}()` with a dynamic module name")

        # env var reads of secrets
        if name in ("os.getenv", "os.environ.get", "os.environ.pop", "os.environ.setdefault") and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and SENSITIVE_ENV_RE.match(a0.value):
                self.add("MG041-secret-env", sev_hi, node, f"reads secret env var `{a0.value}`{where}")

        # writes outside cache dir
        if name in ("open", "io.open", "builtins.open") and self._is_write_mode(node):
            target = node.args[0] if node.args else None
            if target is not None and self._is_outside_path(target):
                self.add("MG050-write-outside", "high", node, f"writes to a path outside the model cache{where}")
        if name.endswith((".write_text", ".write_bytes")) and isinstance(node.func, ast.Attribute):
            if self._is_outside_path(node.func.value):
                self.add("MG050-write-outside", "high", node, f"writes to a path outside the model cache{where}")
        if name in ("os.chmod", "os.chown", "os.symlink", "shutil.copy", "shutil.copyfile", "shutil.move", "os.rename"):
            self.add("MG050-write-outside", "medium", node, f"`{name}()` modifies the filesystem{where}")

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        name = self.resolve(dotted_name(node.value))
        if name == "os.environ" and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            if SENSITIVE_ENV_RE.match(node.slice.value):
                sev = "critical" if self.at_import_time() else "high"
                self.add("MG041-secret-env", sev, node, f"reads secret env var `{node.slice.value}`")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        v = node.value
        if isinstance(v, str):
            if SENSITIVE_PATH_RE.search(v):
                sev = "critical" if self.at_import_time() else "high"
                self.add("MG040-sensitive-path", sev, node, f"references sensitive path `{v[:60]}`")
            if len(v) >= 120 and sum(c.isspace() for c in v) / len(v) < 0.02 and shannon_entropy(v) >= 5.0:
                self.add("MG030-entropy", "high", node,
                         f"long high-entropy string literal ({len(v)} chars, entropy {shannon_entropy(v):.2f}) — possible obfuscated payload")
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


def scan_file(path: Path, rel: str) -> list[Finding]:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src, filename=rel)
    except SyntaxError as e:
        return [Finding("MG001-parse-error", "medium", rel, e.lineno or 0, "", f"could not parse: {e.msg}")]
    lines = src.splitlines()
    v = _Visitor(rel, lines)
    v.visit(tree)
    findings = v.findings

    # module-level side effects
    for stmt in tree.body:
        if not _is_safe_stmt(stmt):
            sev = "medium"
            findings.append(Finding("MG002-module-side-effect", sev, rel, stmt.lineno,
                                    v.snippet(stmt.lineno), "statement runs at import time (outside any def/class)"))
    return findings


def scan_manifest(bundle: CodeBundle) -> list[Finding]:
    out = []
    for e in bundle.auto_map:
        if e.other_repo:
            out.append(Finding("MG060-cross-repo", "high", e.source, 0, f'"{e.auto_class}": "{e.reference}"',
                               f"auto_map pulls code from ANOTHER repo `{e.other_repo}` (supply-chain hop; that code was not analyzed here)",
                               source="manifest"))
        elif not (bundle.root / e.module_file).exists():
            out.append(Finding("MG061-missing-module", "medium", e.source, 0, f'"{e.auto_class}": "{e.reference}"',
                               f"auto_map module `{e.module_file}` is not in the repo", source="manifest"))
    return out


def scan(bundle: CodeBundle) -> list[Finding]:
    findings = scan_manifest(bundle)
    for rel in bundle.py_files:
        findings.extend(scan_file(bundle.root / rel, rel))
    # de-duplicate (same rule/file/line)
    seen, uniq = set(), []
    for f in findings:
        key = (f.rule_id, f.file, f.line, f.message)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return sorted(uniq, key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
