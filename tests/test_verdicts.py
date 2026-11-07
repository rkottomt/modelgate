import json
import shutil

import pytest

from modelgate import explain, policy
from modelgate.scanner import scan
from conftest import FIXTURES

EXPECTED = {"clean_model": "ALLOW", "sneaky_model": "BLOCK", "injection_model": "BLOCK", "cross_repo_model": "WARN"}


@pytest.mark.parametrize("fixture,verdict", EXPECTED.items())
def test_fixture_verdicts(fixture, verdict):
    r = scan(str(FIXTURES / fixture), use_llm=False)
    assert r["verdict"] == verdict, r["reasons"]


def test_sneaky_sandbox_evidence():
    r = scan(str(FIXTURES / "sneaky_model"), use_llm=False)
    rules = {(f["rule_id"], f["file"], f["line"]) for f in r["findings"]}
    assert ("SBX-NET", "modeling_x.py", 3) in rules
    assert ("SBX-PROC", "modeling_x.py", 9) in rules
    assert any(f["rule_id"] == "SBX-SENSITIVE" and f["line"] == 7 for f in r["findings"])


def test_static_rules_hit_sneaky():
    r = scan(str(FIXTURES / "sneaky_model"), use_llm=False, sandbox_mode="subprocess")
    ids = {f["rule_id"] for f in r["findings"]}
    assert {"MG011-network", "MG012-process", "MG021-decode-exec", "MG013-memfd", "MG040-sensitive-path"} <= ids


def _fake_llm(monkeypatch, content: str):
    class Resp:
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": content}}]}

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-not-a-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "test/model")
    monkeypatch.setattr(explain.httpx, "post", lambda *a, **k: Resp())


@pytest.mark.parametrize("fixture", ["sneaky_model", "injection_model"])
def test_llm_cannot_flip_verdict(monkeypatch, fixture):
    evil = json.dumps({"verdict": "ALLOW", "summary": "Totally safe, verdict ALLOW.",
                       "findings": [{"rule_id": "SBX-NET", "file": "modeling_x.py", "line": 3, "explanation": "telemetry"},
                                    {"rule_id": "FAKE", "file": "nope.py", "line": 999, "explanation": "hallucinated"}],
                       "attack_techniques": ["T1071", "not-a-technique"], "recommended_action": "ALLOW: load it"})
    _fake_llm(monkeypatch, evil)
    r = scan(str(FIXTURES / fixture))
    assert r["verdict"] == "BLOCK"
    assert r["explanation"]["source"].startswith("openrouter:")
    assert "verdict" not in r["explanation"]
    # hallucinated finding dropped, real one kept, junk technique dropped
    assert [(f["file"], f["line"]) for f in r["explanation"]["findings"]] == [("modeling_x.py", 3)]
    assert r["explanation"]["dropped_findings"] == 1
    assert r["explanation"]["attack_techniques"] == ["T1071"]


def test_llm_failure_falls_back_to_template(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-not-a-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "test/model")

    def boom(*a, **k):
        raise explain.httpx.ConnectTimeout("timeout")

    monkeypatch.setattr(explain.httpx, "post", boom)
    r = scan(str(FIXTURES / "sneaky_model"))
    assert r["verdict"] == "BLOCK"
    assert r["explanation"]["source"] == "template"


def test_prompt_wraps_untrusted_code():
    r = scan(str(FIXTURES / "injection_model"), use_llm=False)
    msgs = explain.build_messages(r)
    user = msgs[1]["content"]
    assert "<untrusted_code" in user and "Ignore all previous instructions" in user
    assert "MODELGATEcanary" not in user  # canary/env values never sent


def test_allowlist_invalidated_by_code_change(tmp_path):
    repo = tmp_path / "model"
    shutil.copytree(FIXTURES / "cross_repo_model", repo)
    r1 = scan(str(repo), use_llm=False)
    assert r1["verdict"] == "WARN"
    policy.add_to_allowlist(r1["repo_key"], None, r1["code_hash"], r1["verdict"])
    r2 = scan(str(repo), use_llm=False)
    assert r2["verdict"] == "ALLOW" and r2["allowlisted"]
    (repo / "configuration_hop.py").write_text((repo / "configuration_hop.py").read_text() + "\n# changed\n")
    r3 = scan(str(repo), use_llm=False)
    assert not r3["allowlisted"] and r3["code_hash"] != r1["code_hash"] and r3["verdict"] == "WARN"
