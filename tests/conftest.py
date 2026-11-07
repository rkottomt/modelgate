from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MODELGATE_HOME", str(tmp_path / ".modelgate"))
    monkeypatch.setenv("MODELGATE_QUIET", "1")
    monkeypatch.setenv("MODELGATE_LLM", "off")  # never call a real LLM in tests
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("MODELGATE_ALLOW_UNISOLATED", raising=False)
    monkeypatch.delenv("MODELGATE_ALLOW_WARN", raising=False)
    from modelgate import hook
    hook._cleared.clear()
    yield
