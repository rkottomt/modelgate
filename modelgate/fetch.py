"""Download only the code of a model repo (never weights) and resolve auto_map."""
from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

CODE_PATTERNS = ["*.py", "*.json", "*.md", "*.txt"]
AUTO_MAP_FILES = ["config.json", "tokenizer_config.json", "preprocessor_config.json", "processor_config.json"]
MAX_JSON_BYTES = 5_000_000  # tokenizer.json can be huge; we only parse small configs


@dataclass
class AutoMapEntry:
    source: str          # e.g. config.json
    auto_class: str      # e.g. AutoModel
    reference: str       # raw value, e.g. "other/repo--modeling_x.Model"
    module: str          # e.g. modeling_x
    class_name: str
    other_repo: str | None = None   # set when the reference points to another repo

    @property
    def module_file(self) -> str:
        return self.module.replace(".", "/") + ".py"


@dataclass
class CodeBundle:
    target: str
    root: Path
    is_local: bool
    revision: str | None
    files: dict[str, str] = field(default_factory=dict)   # relpath -> sha256
    code_hash: str = ""
    auto_map: list[AutoMapEntry] = field(default_factory=list)

    @property
    def py_files(self) -> list[str]:
        return sorted(f for f in self.files if f.endswith(".py"))

    @property
    def local_modules(self) -> list[str]:
        """auto_map modules that live in this repo (what trust_remote_code would import)."""
        seen: list[str] = []
        for e in self.auto_map:
            if e.other_repo is None and e.module not in seen and (self.root / e.module_file).exists():
                seen.append(e.module)
        return seen

    def to_dict(self) -> dict:
        d = asdict(self)
        d["root"] = str(self.root)
        return d


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_reference(ref: str) -> tuple[str | None, str, str]:
    """'org/repo--mod.sub.Class' -> ('org/repo', 'mod.sub', 'Class')."""
    other = None
    if "--" in ref:
        other, ref = ref.split("--", 1)
    module, _, cls = ref.rpartition(".")
    return other, module, cls


def parse_auto_map(root: Path) -> list[AutoMapEntry]:
    entries: list[AutoMapEntry] = []
    for name in AUTO_MAP_FILES:
        p = root / name
        if not p.is_file() or p.stat().st_size > MAX_JSON_BYTES:
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        amap = data.get("auto_map") if isinstance(data, dict) else None
        if not isinstance(amap, dict):
            continue
        for auto_class, value in amap.items():
            refs = value if isinstance(value, list) else [value]
            for ref in refs:
                if not isinstance(ref, str) or "." not in ref:
                    continue
                other, module, cls = parse_reference(ref)
                entries.append(AutoMapEntry(name, auto_class, ref, module, cls, other))
    return entries


def fetch(target: str, revision: str | None = None, cache_dir: str | None = None) -> CodeBundle:
    """Fetch code-only files for a HF repo id, or wrap a local directory."""
    local = Path(target).expanduser()
    if local.is_dir():
        root, is_local = local.resolve(), True
    else:
        from huggingface_hub import snapshot_download

        dest = Path(cache_dir) if cache_dir else Path(tempfile.mkdtemp(prefix="modelgate_"))
        root = Path(
            snapshot_download(
                repo_id=target,
                revision=revision,
                allow_patterns=CODE_PATTERNS,
                local_dir=str(dest / target.replace("/", "__")),
            )
        )
        is_local = False

    files: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or rel.startswith(".") or "/." in rel or "__pycache__" in rel:
            continue
        if p.suffix in (".py", ".json", ".md", ".txt"):
            files[rel] = _sha256(p)

    combined = hashlib.sha256()
    for rel, digest in sorted(files.items()):
        if rel.endswith((".py", ".json")):  # code + config determine behavior
            combined.update(f"{rel}\0{digest}\n".encode())

    return CodeBundle(
        target=target,
        root=root,
        is_local=is_local,
        revision=revision,
        files=files,
        code_hash=combined.hexdigest(),
        auto_map=parse_auto_map(root),
    )
