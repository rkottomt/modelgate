import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MODELGATE_HOME", str(tmp_path / ".modelgate"))
    monkeypatch.setenv("MODELGATE_QUIET", "1")
    # never call the real LLM in tests
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    yield
