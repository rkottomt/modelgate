"""Monkeypatch Transformers so every trust_remote_code load is scanned first."""
from __future__ import annotations

import functools
import importlib
import os
import sys

from . import ModelGateBlocked, ModelGateWarn

_installed = False
_cleared: set[tuple[str, str | None]] = set()

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
]
AUTO_CLASSES = ["AutoConfig", "AutoModel", "AutoModelForCausalLM", "AutoModelForSeq2SeqLM", "AutoModelForSequenceClassification",
                "AutoModelForMaskedLM", "AutoModelForTokenClassification", "AutoModelForImageClassification",
                "AutoTokenizer", "AutoProcessor", "AutoImageProcessor", "AutoFeatureExtractor"]


def _headline(report: dict) -> str:
    """One-line human summary of the strongest evidence."""
    parts = []
    for f in report["findings"]:
        if f["severity"] != "critical" or len(parts) >= 4:
            continue
        r = f["rule_id"]
        loc = f"{f['file']} line {f['line']}"
        if r == "SBX-NET":
            parts.append(f"{loc} attempts socket.connect to {f['snippet'].replace('connect to ', '')}")
        elif r == "SBX-SENSITIVE":
            parts.append(f"{loc} reads decoy ~/.ssh/id_rsa" if "id_rsa" in f["snippet"] else f"{loc} reads {f['snippet']}")
        elif r == "SBX-PROC":
            parts.append(f"{loc} spawns {f['snippet'].split()[1] if len(f['snippet'].split()) > 1 else 'a process'}")
        elif r == "SBX-CANARY":
            parts.append(f"{loc} reads canary credential")
        elif r.startswith("SBX-") or not any(p.startswith(loc) for p in parts):
            if r.startswith("SBX-") or r.startswith("MG"):
                parts.append(f"{loc}: {f['message']}")
    return "; ".join(parts[:4]) or "; ".join(report["reasons"][:3])


def gate(target: str, revision: str | None = None) -> dict | None:
    """Scan `target` and raise on BLOCK (or WARN without MODELGATE_ALLOW_WARN=1)."""
    from .scanner import repo_key, scan

    key = (repo_key(str(target)), revision)
    if key in _cleared:
        return None
    report = scan(str(target), revision)
    quiet = os.environ.get("MODELGATE_QUIET") == "1"
    if not quiet and report["verdict"] != "ALLOW":
        from rich.console import Console

        from .cli import render
        render(report, Console(stderr=True))
    if report["verdict"] == "BLOCK":
        raise ModelGateBlocked(f"ModelGate BLOCKED {target}: {_headline(report)}. Report: {report['report_path']}",
                               report["report_path"], report)
    if report["verdict"] == "WARN" and os.environ.get("MODELGATE_ALLOW_WARN") != "1":
        raise ModelGateWarn(f"ModelGate WARN for {target}: review the report, then set MODELGATE_ALLOW_WARN=1 or run "
                            f"`modelgate allow {target}`. Report: {report['report_path']}", report["report_path"], report)
    _cleared.add(key)
    return report


def _wrap_dynamic(orig):
    if getattr(orig, "_modelgate", False):
        return orig

    @functools.wraps(orig)
    def wrapper(class_reference, pretrained_model_name_or_path, *args, **kwargs):
        revision = kwargs.get("code_revision") or kwargs.get("revision")
        if "--" in class_reference:  # code lives in ANOTHER repo: scan that one too
            gate(class_reference.split("--", 1)[0], revision)
        gate(str(pretrained_model_name_or_path), revision)
        return orig(class_reference, pretrained_model_name_or_path, *args, **kwargs)

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
            gate(str(pretrained_model_name_or_path), kwargs.get("code_revision") or kwargs.get("revision"))
        return func(klass, pretrained_model_name_or_path, *args, **kwargs)

    from_pretrained._modelgate = True
    cls.from_pretrained = classmethod(from_pretrained)


def install() -> None:
    global _installed
    if _installed:
        return
    dmu = importlib.import_module("transformers.dynamic_module_utils")
    wrapped = _wrap_dynamic(dmu.get_class_from_dynamic_module)
    for name in DYNAMIC_USERS:
        try:
            mod = importlib.import_module(name)
        except Exception:  # noqa: BLE001  optional pieces (e.g. video) may be missing
            continue
        if hasattr(mod, "get_class_from_dynamic_module"):
            mod.get_class_from_dynamic_module = wrapped
    import transformers

    for name in AUTO_CLASSES:
        try:
            _wrap_from_pretrained(getattr(transformers, name))
        except Exception:  # noqa: BLE001
            continue
    _installed = True
    if os.environ.get("MODELGATE_QUIET") != "1":
        print("[modelgate] gate installed: trust_remote_code loads will be scanned first", file=sys.stderr)
