"""Agent guardrails: LLM output is validated as data, contracts are signed, checks are deterministic."""
from pathlib import Path

import pytest

from modelgate import agents, guardrails as gr, sandbox

AG = Path(__file__).resolve().parents[1] / "examples" / "agents"
needs_docker = pytest.mark.skipif(not sandbox.docker_available(), reason="needs Docker sandbox image")


def test_normalize_drops_unknown_and_defaults_closed():
    rails = {g.id: g for g in gr.normalize([{"id": "evil", "enabled": True, "params": {"code": "rm -rf /"}},
                                            {"id": "no_network", "enabled": False}])}
    assert "evil" not in rails
    assert rails["no_network"].enabled is False          # explicit choice kept
    assert rails["no_secrets"].enabled is True           # missing => default on


def test_wildcard_hosts_rejected_and_empty_allowlist_reverts():
    rails = {g.id: g for g in gr.normalize([{"id": "allowed_hosts", "enabled": True, "params": {"hosts": ["*", "*.com", "0.0.0.0/0"]}},
                                            {"id": "no_network", "enabled": True}])}
    assert rails["allowed_hosts"].params["hosts"] == []
    assert rails["allowed_hosts"].enabled is False and rails["no_network"].enabled is True


def test_limits_are_clamped():
    rails = {g.id: g for g in gr.normalize([{"id": "max_runtime", "enabled": True, "params": {"seconds": 10**9}}])}
    assert rails["max_runtime"].params["seconds"] == 600


def test_contract_signature_detects_tampering():
    c = gr.sign("x", "hash", [])
    assert gr.verify(c)
    c["guardrails"][0]["enabled"] = not c["guardrails"][0]["enabled"]
    assert not gr.verify(c)


def test_code_change_voids_contract():
    c = gr.sign("rogue_eval_agent", "not-the-real-hash", [])
    r = agents.run(AG / "rogue_eval_agent", c)
    assert r["verdict"] == "BLOCK" and not r["contract_valid"]


@needs_docker
def test_rogue_agent_violations_and_clean_agent_passes():
    for name, expect in (("rogue_eval_agent", "BLOCK"), ("data_cleaner", "ALLOW")):
        p = agents.propose(AG / name)
        r = agents.run(AG / name, gr.sign(p["agent"], p["code_hash"], p["guardrails"]))
        assert r["verdict"] == expect, r["reasons"]
    rules = {(f["rule_id"], f["line"]) for f in r_rogue()["findings"]}
    assert {("GR-no_network", 17), ("GR-no_secrets", 23), ("GR-no_secrets", 25),
            ("GR-workspace_writes_only", 31), ("GR-no_subprocess", 36)} <= rules


def r_rogue():
    p = agents.propose(AG / "rogue_eval_agent")
    return agents.run(AG / "rogue_eval_agent", gr.sign(p["agent"], p["code_hash"], p["guardrails"]))
