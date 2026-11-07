import pytest

from modelgate import ModelGateBlocked, ModelGateWarn
from conftest import FIXTURES


def test_from_pretrained_blocks_sneaky():
    import modelgate.auto  # noqa: F401
    from transformers import AutoConfig, AutoModel

    with pytest.raises(ModelGateBlocked) as ei:
        AutoModel.from_pretrained(str(FIXTURES / "sneaky_model"), trust_remote_code=True)
    assert "modeling_x.py line 3" in str(ei.value) and ei.value.report_path
    with pytest.raises(ModelGateBlocked):
        AutoConfig.from_pretrained(str(FIXTURES / "injection_model"), trust_remote_code=True)


def test_warn_requires_opt_in(monkeypatch):
    import modelgate.auto  # noqa: F401
    from modelgate import hook
    from transformers import AutoConfig

    hook._cleared.clear()
    with pytest.raises(ModelGateWarn):
        AutoConfig.from_pretrained(str(FIXTURES / "cross_repo_model"), trust_remote_code=True)


def test_clean_passes_gate():
    import modelgate.auto  # noqa: F401
    from transformers import AutoConfig

    cfg = AutoConfig.from_pretrained(str(FIXTURES / "clean_model"), trust_remote_code=True)
    assert type(cfg).__name__ == "TinyCleanConfig"
