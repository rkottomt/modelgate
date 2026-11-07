"""Monkeypatch Transformers so every trust_remote_code load is scanned first, pinned, and verified.

Choke points patched:
  1. Auto*.from_pretrained(trust_remote_code=True)   -> scan, then force revision=<scanned SHA>
  2. dynamic_module_utils.get_class_from_dynamic_module  -> scan (incl. cross-repo "org/repo--mod.Class")
  3. dynamic_module_utils.get_cached_module_file     -> scan the repo it is about to copy code from,
     force revision=<scanned SHA>, and after the copy into HF_MODULES_CACHE verify the file's sha256
     matches what we scanned BEFORE transformers imports it.
Out of scope: diffusers / vLLM / other loaders that don't go through transformers.dynamic_module_utils.
"""
from __future__ import annotations

import functools
import hashlib
import importlib
import inspect
import os
import re
import sys
from pathlib import Path

from . import ModelGateBlocked, ModelGateWarn

_installed = False
_cleared: dict[str, dict] = {}   # repo_key -> report that passed the gate

DYNAMIC_USERS = [
    "transformers.dynamic_module_utils",
    "transformers.models.auto.auto_factory",
    "transformers.models.auto.configuration_auto",
    "transformers.models.auto.tokenization_auto",
    "transformers.models.auto.feature_extraction_auto",
    "transformers.models.auto.image_processing_auto",
    "transformers.models.auto.processing_auto",
    "transformers.models.auto.video_processing_auto",
    "transformers.pipelines",
    "transformers.generation.utils",
]
AUTO_CLASSES = ["AutoConfig", "AutoModel", "AutoModelForCausalLM", "AutoModelForSeq2SeqLM", "AutoModelForSequenceClassification",
                "AutoModelForMaskedLM", "AutoModelForTokenClassification", "AutoModelForImageClassification",
                "AutoTokenizer", "AutoProcessor", "AutoImageProcessor", "AutoFeatureExtractor"]


def _headline(report: dict) -> str:
    parts = []
    for f in report["findings"]:
        if f["severity"] != "critical" or len(parts) >= 4:
            continue
        r, loc = f["rule_id"], f"{f['file']} line {f['line']}"
        if r == "SBX-NET":
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[\w.-]+\.\w+)'?,?\s*:?\s*(\d+)?", f["snippet"].replace("connect to", ""))
            dest = f"{m.group(1)}:{m.group(2)}" if m and m.group(2) else (m.group(1) if m else f["snippet"])
            parts.append(f"{loc} attempts socket.connect to {dest}")
        elif r == "SBX-SENSITIVE":
            parts.append(f"{loc} reads decoy ~/.ssh/id_rsa" if "id_rsa" in f["snippet"] else f"{loc} reads {f['snippet']}")
        elif r == "SBX-PROC":
            exe = f["snippet"].split()[1] if len(f["snippet"].split()) > 1 else "a process"
            parts.append(f"{loc} spawns {exe.strip(chr(34))}")
        elif r.startswith(("SBX-", "MG")):
            parts.append(f"{loc}: {f['message']}")
    return "; ".join(parts) or "; ".join(report["reasons"][:3])


def _revs(rev) -> set:
    return {str(x) for x in (rev, getattr(rev, "initial", None), getattr(rev, "resolved", None)) if x}


def gate(target: str, revision=None) -> dict:
    """Scan `target` (once per process per revision); raise on BLOCK, or WARN without MODELGATE_ALLOW_WARN=1."""
    from .scanner import repo_key, scan

    key = repo_key(str(target))
    cached = _cleared.get(key)
    if cached and (not _revs(revision) or _revs(revision) & {str(cached.get("revision")), str(cached.get("sha"))}):
        return cached
    rev = getattr(revision, "resolved", None) or (str(revision) if revision else None)
    report = scan(str(target), rev)
    if os.environ.get("MODELGATE_QUIET") != "1" and report["verdict"] != "ALLOW":
        from rich.console import Console

        from .cli import render
        render(report, Console(stderr=True))
    if report["verdict"] == "BLOCK":
        raise ModelGateBlocked(f"ModelGate BLOCKED {target}: {_headline(report)}. Report: {report['report_path']}",
                               report["report_path"], report)
    if report["verdict"] == "WARN" and os.environ.get("MODELGATE_ALLOW_WARN") != "1":
        raise ModelGateWarn(f"ModelGate WARN for {target}: review the report, then set MODELGATE_ALLOW_WARN=1 or run "
                            f"`modelgate allow {target}`. Report: {report['report_path']}", report["report_path"], report)
    _cleared[key] = report
    return report


def verify_cached_module(report: dict, module_file: str, cached_path: str) -> None:
    """The file transformers is about to import must be byte-identical to what we scanned."""
    from transformers.dynamic_module_utils import HF_MODULES_CACHE

    p = Path(cached_path)
    if not p.is_absolute():
        p = Path(HF_MODULES_CACHE) / cached_path
    scanned = report.get("bundle", {}).get("files", {})
    targets = [(module_file, p)]
    # relative imports were copied next to it; verify those too
    for sib in p.parent.glob("*.py"):
        rel = (Path(module_file).parent / sib.name).as_posix()
        if rel != module_file and rel in scanned:
            targets.append((rel, sib))
    for rel, path in targets:
        expected = scanned.get(rel)
        if report.get("allowlisted") and expected is None:
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        if expected is None or actual != expected:
            raise ModelGateBlocked(f"ModelGate BLOCKED: cached module {path} does not match the scanned code "
                                   f"(expected {str(expected)[:12]}, got {str(actual)[:12]}). Refusing to import.",
                                   report.get("report_path"), report)


def _bind(orig, args, kwargs):
    ba = inspect.signature(orig).bind_partial(*args, **kwargs)
    return ba


def _wrap_cached_module_file(orig):
    if getattr(orig, "_modelgate", False):
        return orig

    @functools.wraps(orig)
    def wrapper(*args, **kwargs):
        ba = _bind(orig, args, kwargs)
        repo = str(ba.arguments["pretrained_model_name_or_path"])
        module_file = ba.arguments["module_file"]
        report = gate(repo, ba.arguments.get("revision"))
        if report.get("sha"):
            ba.arguments["revision"] = report["sha"]   # pin: transformers fetches exactly what we scanned
        result = orig(*ba.args, **ba.kwargs)
        verify_cached_module(report, module_file, result)
        return result

    wrapper._modelgate = True
    return wrapper


def _wrap_dynamic(orig):
    if getattr(orig, "_modelgate", False):
        return orig

    @functools.wraps(orig)
    def wrapper(*args, **kwargs):
        ba = _bind(orig, args, kwargs)
        ref = ba.arguments["class_reference"]
        path = str(ba.arguments["pretrained_model_name_or_path"])
        rev = ba.arguments.get("code_revision") or ba.arguments.get("revision")
        report = gate(path, rev)
        if "--" in ref:
            gate(ref.split("--", 1)[0], None)   # code from ANOTHER repo: scanned + pinned in get_cached_module_file
        elif report.get("sha"):
            ba.arguments["code_revision"] = report["sha"]
        return orig(*ba.args, **ba.kwargs)

    wrapper._modelgate = True
    return wrapper


def _wrap_from_pretrained(cls):
    orig = cls.__dict__.get("from_pretrained")
    if orig is None:
        return
    func = orig.__func__ if isinstance(orig, classmethod) else orig
    if getattr(func, "_modelgate", False):
        return

    @functools.wraps(func)
    def from_pretrained(klass, pretrained_model_name_or_path, *args, **kwargs):
        if kwargs.get("trust_remote_code"):
            report = gate(str(pretrained_model_name_or_path), kwargs.get("code_revision") or kwargs.get("revision"))
            if report.get("sha"):
                kwargs["revision"] = report["sha"]   # pin weights + code to the scanned commit
                if "code_revision" in kwargs:
                    kwargs["code_revision"] = report["sha"]
        return func(klass, pretrained_model_name_or_path, *args, **kwargs)

    from_pretrained._modelgate = True
    cls.from_pretrained = classmethod(from_pretrained)


def install() -> None:
    global _installed
    if _installed:
        return
    dmu = importlib.import_module("transformers.dynamic_module_utils")
    wrapped_cls = _wrap_dynamic(dmu.get_class_from_dynamic_module)
    wrapped_file = _wrap_cached_module_file(dmu.get_cached_module_file)
    for name in DYNAMIC_USERS:
        try:
            mod = importlib.import_module(name)
        except Exception:  # noqa: BLE001  optional pieces may be missing
            continue
        if hasattr(mod, "get_class_from_dynamic_module"):
            mod.get_class_from_dynamic_module = wrapped_cls
        if hasattr(mod, "get_cached_module_file"):
            mod.get_cached_module_file = wrapped_file
    import transformers

    for name in AUTO_CLASSES:
        try:
            _wrap_from_pretrained(getattr(transformers, name))
        except Exception:  # noqa: BLE001
            continue
    _installed = True
    if os.environ.get("MODELGATE_QUIET") != "1":
        print("[modelgate] gate installed: trust_remote_code loads will be scanned, pinned and verified", file=sys.stderr)
