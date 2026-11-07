"""Fetch every non-weight file of a model repo at a PINNED commit SHA and resolve code references.

Security properties:
- remote repos are resolved to an immutable commit SHA first; everything downstream uses the SHA
- weights (*.safetensors, *.bin, *.pt, *.gguf) are never downloaded
- symlinks are rejected; every path is realpath-checked to stay inside the snapshot
- native/compiled code (.so/.pyd/.dll/.dylib/.pyc) is detected from the repo listing (BLOCK)
- files over MAX_FILE_BYTES are not parsed; oversized code/config files are a fail-closed finding
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

WEIGHT_PATTERNS = ["*.safetensors", "*.bin", "*.pt", "*.gguf"]
WEIGHT_SUFFIXES = (".safetensors", ".bin", ".pt", ".gguf")
NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib", ".pyc", ".pyo")
MAX_FILE_BYTES = 2 * 1024 * 1024
AUTO_MAP_FILES = ["config.json", "tokenizer_config.json", "preprocessor_config.json", "processor_config.json",
                  "feature_extractor_config.json", "image_processor_config.json", "video_preprocessor_config.json"]


class FetchError(RuntimeError):
    pass


@dataclass
class CodeRef:
    """A piece of code the repo tells transformers to execute."""
    source: str          # file the reference came from, e.g. config.json
    kind: str            # auto_map | custom_pipelines | custom_generate
    key: str             # e.g. AutoModel / text-classification
    reference: str       # raw value, e.g. "other/repo--modeling_x.Model"
    module: str          # e.g. modeling_x
    class_name: str
    other_repo: str | None = None

    @property
    def module_file(self) -> str:
        return self.module.replace(".", "/") + ".py"


# Backwards-compatible name used by the rest of the code
AutoMapEntry = CodeRef


@dataclass
class FileIssue:
    kind: str     # symlink | escape | native | oversized | unreadable
    path: str
    detail: str


@dataclass
class CodeBundle:
    target: str
    root: Path
    is_local: bool
    revision: str | None            # what the user asked for
    sha: str | None = None          # pinned commit SHA (None for local dirs)
    files: dict[str, str] = field(default_factory=dict)   # relpath -> sha256
    code_hash: str = ""
    auto_map: list[CodeRef] = field(default_factory=list)
    issues: list[FileIssue] = field(default_factory=list)
    skipped_large: list[str] = field(default_factory=list)

    @property
    def py_files(self) -> list[str]:
        return sorted(f for f in self.files if f.endswith(".py"))

    @property
    def local_modules(self) -> list[str]:
        """Modules in this repo that transformers would import."""
        seen: list[str] = []
        for e in self.auto_map:
            if e.other_repo is None and e.module not in seen and e.module_file in self.files:
                seen.append(e.module)
        return seen

    @property
    def other_repos(self) -> list[str]:
        out: list[str] = []
        for e in self.auto_map:
            if e.other_repo and e.other_repo not in out:
                out.append(e.other_repo)
        return out

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


def _load_json(p: Path):
    if not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return None


def _add(entries: list[CodeRef], source: str, kind: str, key: str, ref) -> None:
    if not isinstance(ref, str) or "." not in ref:
        return
    other, module, cls = parse_reference(ref)
    entries.append(CodeRef(source, kind, str(key), ref, module, cls, other))


def parse_code_refs(root: Path) -> list[CodeRef]:
    entries: list[CodeRef] = []
    for name in AUTO_MAP_FILES:
        data = _load_json(root / name)
        if not isinstance(data, dict):
            continue
        amap = data.get("auto_map")
        if isinstance(amap, dict):
            for auto_class, value in amap.items():
                for ref in value if isinstance(value, list) else [value]:
                    _add(entries, name, "auto_map", auto_class, ref)
        pipes = data.get("custom_pipelines")
        if isinstance(pipes, dict):
            for task, spec in pipes.items():
                if isinstance(spec, dict):
                    _add(entries, name, "custom_pipelines", task, spec.get("impl"))
                    for fw in ("pt", "tf"):
                        for ref in spec.get(fw) or [] if isinstance(spec.get(fw), list) else [spec.get(fw)]:
                            if isinstance(ref, str) and "--" in ref:
                                _add(entries, name, "custom_pipelines", task, ref)
    # custom_generate: a repo-local custom_generate/generate.py, or a pointer to another repo
    if (root / "custom_generate" / "generate.py").is_file():
        entries.append(CodeRef("custom_generate/generate.py", "custom_generate", "generate",
                               "custom_generate.generate.generate", "custom_generate.generate", "generate"))
    gen = _load_json(root / "generation_config.json")
    if isinstance(gen, dict) and isinstance(gen.get("custom_generate"), str):
        repo = gen["custom_generate"]
        entries.append(CodeRef("generation_config.json", "custom_generate", "generate", repo,
                               "custom_generate.generate", "generate", repo))
    return entries


# kept for callers/tests using the old name
parse_auto_map = parse_code_refs


def resolve_revision(repo_id: str, revision: str | None) -> tuple[str, list[dict]]:
    """Resolve branch/tag to an immutable commit SHA and get the file listing (with sizes)."""
    from huggingface_hub import HfApi

    info = HfApi().model_info(repo_id, revision=revision, files_metadata=True)
    if not info.sha:
        raise FetchError(f"could not resolve {repo_id}@{revision or 'main'} to a commit SHA")
    listing = [{"path": s.rfilename, "size": getattr(s, "size", None) or 0} for s in (info.siblings or [])]
    return info.sha, listing


def _walk_checked(root: Path, issues: list[FileIssue]) -> list[tuple[str, Path]]:
    """Every regular file under root, rejecting symlinks and path escapes."""
    real_root = os.path.realpath(root)
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                issues.append(FileIssue("symlink", os.path.relpath(full, root), "symlinked directory"))
                dirnames.remove(d)
            elif d in (".git", ".cache", "__pycache__"):
                dirnames.remove(d)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                # HF's local_dir mode never uses symlinks; local repos must not either
                issues.append(FileIssue("symlink", rel, f"symlink -> {os.readlink(full)}"))
                continue
            if os.path.commonpath([real_root, os.path.realpath(full)]) != real_root:
                issues.append(FileIssue("escape", rel, "resolves outside the snapshot"))
                continue
            out.append((rel, Path(full)))
    return out


def fetch(target: str, revision: str | None = None, cache_dir: str | None = None) -> CodeBundle:
    """Fetch non-weight files for a HF repo id (pinned to a SHA), or wrap a local directory."""
    local = Path(target).expanduser()
    issues: list[FileIssue] = []
    skipped: list[str] = []
    sha = None
    if local.is_dir():
        root, is_local = local.resolve(), True
    else:
        from huggingface_hub import snapshot_download

        sha, listing = resolve_revision(target, revision)
        ignore = list(WEIGHT_PATTERNS)
        for f in listing:
            p = f["path"]
            if p.endswith(NATIVE_SUFFIXES):
                issues.append(FileIssue("native", p, "compiled/native code in repo"))
            if not p.endswith(WEIGHT_SUFFIXES) and f["size"] > MAX_FILE_BYTES:
                if p.endswith((".py", ".json")) and not p.endswith("tokenizer.json"):
                    issues.append(FileIssue("oversized", p, f"{f['size']} bytes > {MAX_FILE_BYTES} cap"))
                skipped.append(p)
                ignore.append(p)  # never download large non-code blobs (e.g. tokenizer.json, onnx)
        dest = Path(cache_dir) if cache_dir else Path(tempfile.mkdtemp(prefix="modelgate_"))
        root = Path(snapshot_download(repo_id=target, revision=sha, ignore_patterns=ignore,
                                      local_dir=str(dest / f"{target.replace('/', '__')}__{sha[:12]}"))).resolve()
        is_local = False

    files: dict[str, str] = {}
    for rel, p in _walk_checked(root, issues):
        if rel.endswith(NATIVE_SUFFIXES) and not any(i.path == rel and i.kind == "native" for i in issues):
            issues.append(FileIssue("native", rel, "compiled/native code in repo"))
        if rel.endswith(WEIGHT_SUFFIXES):
            continue
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            if rel.endswith((".py", ".json")) and not rel.endswith("tokenizer.json"):
                if not any(i.path == rel for i in issues):
                    issues.append(FileIssue("oversized", rel, f"{size} bytes > {MAX_FILE_BYTES} cap"))
            skipped.append(rel)
            continue
        try:
            files[rel] = _sha256(p)
        except OSError as e:
            issues.append(FileIssue("unreadable", rel, type(e).__name__))

    combined = hashlib.sha256()
    for rel, digest in sorted(files.items()):
        combined.update(f"{rel}\0{digest}\n".encode())

    return CodeBundle(target=target, root=root, is_local=is_local, revision=revision, sha=sha, files=files,
                      code_hash=combined.hexdigest(), auto_map=parse_code_refs(root), issues=issues,
                      skipped_large=sorted(set(skipped)))
