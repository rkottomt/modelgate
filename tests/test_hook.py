import shutil

import pytest

from modelgate import ModelGateBlocked, ModelGateWarn
from conftest import FIXTURES


def test_from_pretrained_blocks_sneaky():
    import modelgate.auto  # noqa: F401
    from transformers import AutoConfig, AutoModel

    with pytest.raises(ModelGateBlocked) as ei:
        AutoModel.from_pretrained(str(FIXTURES / "sneaky_model"), trust_remote_code=True)
    assert "modeling_x.py line 3 attempts socket.connect to 203.0.113.5" in str(ei.value) and ei.value.report_path
    with pytest.raises(ModelGateBlocked):
        AutoConfig.from_pretrained(str(FIXTURES / "injection_model"), trust_remote_code=True)


def test_low_level_hook_blocks_without_from_pretrained():
    import modelgate.auto  # noqa: F401
    from transformers.dynamic_module_utils import get_cached_module_file, get_class_from_dynamic_module

    with pytest.raises(ModelGateBlocked):
        get_cached_module_file(str(FIXTURES / "deferred_model"), "modeling_lazy.py")
    with pytest.raises(ModelGateBlocked):
        get_class_from_dynamic_module("modeling_x.XNetModel", str(FIXTURES / "sneaky_model"))


def test_warn_requires_opt_in(monkeypatch):
    import modelgate.auto  # noqa: F401
    from transformers import AutoConfig

    with pytest.raises(ModelGateWarn):
        AutoConfig.from_pretrained(str(FIXTURES / "warn_model"), trust_remote_code=True)
    monkeypatch.setenv("MODELGATE_ALLOW_WARN", "1")
    cfg = AutoConfig.from_pretrained(str(FIXTURES / "warn_model"), trust_remote_code=True)
    assert type(cfg).__name__ == "VocabNetConfig"


def test_clean_passes_gate():
    import modelgate.auto  # noqa: F401
    from transformers import AutoConfig

    cfg = AutoConfig.from_pretrained(str(FIXTURES / "clean_model"), trust_remote_code=True)
    assert type(cfg).__name__ == "TinyCleanConfig"


def test_cached_module_hash_mismatch_blocks(tmp_path):
    from modelgate.hook import verify_cached_module
    from modelgate.scanner import scan

    report = scan(str(FIXTURES / "clean_model"), use_llm=False)
    good = tmp_path / "configuration_tinyclean.py"
    shutil.copy(FIXTURES / "clean_model" / "configuration_tinyclean.py", good)
    verify_cached_module(report, "configuration_tinyclean.py", str(good))   # identical: ok
    good.write_text(good.read_text() + "\nimport os; os.system('echo swapped')\n")
    with pytest.raises(ModelGateBlocked):
        verify_cached_module(report, "configuration_tinyclean.py", str(good))
