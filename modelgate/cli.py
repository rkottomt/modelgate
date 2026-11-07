"""ModelGate CLI: scan / allow / guardrails / run / serve."""
from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import policy
from .scanner import repo_key, scan as run_scan

app = typer.Typer(add_completion=False, help="ModelGate: a safety gate for trust_remote_code model loads.")
console = Console()

COLORS = {"BLOCK": "bold white on red", "WARN": "bold black on yellow", "ALLOW": "bold white on green"}
SEV = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}


def render(report: dict, con: Console | None = None) -> None:
    con = con or console
    v = report["verdict"]
    sb = report["sandbox"]
    pin = f"sha {report['sha'][:12]}" if report.get("sha") else "local dir"
    sub = f"{report['target']}  ·  {pin}  ·  code {(report.get('code_hash') or '')[:12]}  ·  {report['scan_seconds']}s"
    con.print(Panel(Text(f"\n{v}\n", justify="center", style=COLORS[v]), subtitle=sub, style=COLORS[v].split(" on ")[-1], padding=(0, 2)))

    if report.get("allowlisted"):
        con.print("[green]Allowlisted: repo + pinned SHA + code hash match a signed (HMAC) entry. Code unchanged since approval.[/]")
        return

    if sb["mode"] in ("subprocess", "none"):
        con.print(Panel(f"[bold]NOT ISOLATED[/]: {sb.get('note', '')}", style="bold red"))

    refs = report.get("references") or []
    if refs:
        t = Table(title="Referenced repos (scanned recursively, pinned)", expand=True)
        for c in ("Repo", "SHA", "Verdict", "Why"):
            t.add_column(c, overflow="fold")
        for r in refs:
            t.add_row(r["target"], (r.get("sha") or "-")[:12], Text(r["verdict"], style=COLORS[r["verdict"]]),
                      "; ".join(r.get("reasons") or [])[:160])
        con.print(t)

    findings = [f for f in report["findings"] if f["severity"] != "low"]
    if findings:
        t = Table(title=f"Findings ({len(findings)})", show_lines=False, expand=True)
        t.add_column("Sev", no_wrap=True)
        t.add_column("Rule", no_wrap=True)
        t.add_column("Where", no_wrap=True)
        t.add_column("What")
        t.add_column("Code", overflow="fold", style="cyan")
        for f in findings:
            where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            t.add_row(Text(f["severity"].upper(), style=SEV[f["severity"]]), f["rule_id"], where, f["message"], f["snippet"][:90])
        con.print(t)

    ev = [e for e in sb.get("events", []) if e["event"] not in ("module.imported",)]
    if ev:
        t = Table(title=f"Sandbox timeline ({sb['mode']}{' + strace' if sb.get('strace') else ''}, status: {sb['status']})", expand=True)
        t.add_column("t (s)", justify="right", no_wrap=True)
        t.add_column("Src", no_wrap=True)
        t.add_column("Phase", no_wrap=True)
        t.add_column("Event", no_wrap=True)
        t.add_column("Where", no_wrap=True)
        t.add_column("Detail", overflow="fold")
        for e in ev[:40]:
            where = f"{e['file']}:{e['line']}" if e.get("file") else ""
            style = "red" if e["event"] in policy.NET_EVENTS | policy.PROC_EVENTS | {"env.read", "os.memfd_create", "memfd_create"} else ""
            phase = e.get("phase") or ""
            t.add_row(f"{e['t']:.3f}", e.get("source", "audit"), phase, Text(e["event"], style=style), where, e["detail"][:120])
        con.print(t)
    elif sb["status"] == "skipped":
        con.print(f"[dim]Sandbox skipped: {sb.get('note')}[/]")

    exp = report.get("explanation")
    if exp:
        body = [Text(exp.get("summary", ""), style="bold")]
        for f in exp.get("findings", [])[:8]:
            body.append(Text(f"• {f['file']}:{f['line']} [{f['rule_id']}] {f['explanation']}"))
        if exp.get("attack_techniques"):
            body.append(Text("MITRE ATT&CK: " + ", ".join(exp["attack_techniques"]), style="magenta"))
        if exp.get("recommended_action"):
            body.append(Text("Recommended: " + exp["recommended_action"], style="italic"))
        con.print(Panel(Group(*body), title="AI explanation (advisory; does not affect verdict)",
                        subtitle=f"source: {exp.get('source')}", border_style="blue"))
    con.print(f"[dim]Report: {report.get('report_path')}[/]")


@app.command()
def scan(target: str = typer.Argument(..., help="HF repo id (org/name) or local directory"),
         revision: Optional[str] = typer.Option(None, "--revision", "-r"),
         as_json: bool = typer.Option(False, "--json", help="print the JSON report"),
         no_llm: bool = typer.Option(False, "--no-llm", help="skip the AI explanation"),
         sandbox: Optional[str] = typer.Option(None, "--sandbox", help="force 'docker' or 'subprocess'")):
    """Scan a model repo's remote code and print a verdict."""
    with console.status("[bold]Scanning: fetch code → static AST → sandbox → policy → explain…"):
        report = run_scan(target, revision, use_llm=not no_llm, sandbox_mode=sandbox)
    if as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        render(report)
    raise typer.Exit(code={"ALLOW": 0, "WARN": 1, "BLOCK": 2}[report["verdict"]])


@app.command()
def allow(target: str = typer.Argument(..., help="HF repo id or local directory"),
          revision: Optional[str] = typer.Option(None, "--revision", "-r"),
          force: bool = typer.Option(False, "--force", help="allow even if the verdict is BLOCK")):
    """Approve the CURRENT code of a repo. Any code change invalidates the approval."""
    report = run_scan(target, revision, use_llm=False, use_allowlist=False)
    if report["verdict"] == "BLOCK" and not force:
        render(report)
        console.print("[bold red]Refusing to allowlist a BLOCK verdict. Use --force if you are sure.[/]")
        raise typer.Exit(2)
    policy.add_to_allowlist(repo_key(target), report.get("sha"), report["code_hash"], report["verdict"])
    console.print(f"[green]Allowlisted {target} @ {(report.get('sha') or 'local')[:12]} (code hash {report['code_hash'][:12]}, "
                  f"verdict was {report['verdict']}).[/] Stored in {policy.allowlist_path()}")


@app.command()
def guardrails(agent_dir: str = typer.Argument(..., help="folder with the agent's code (agent.py, agent.json)"),
               goal: Optional[str] = typer.Option(None, "--goal", "-g", help="what the agent is supposed to do"),
               out: str = typer.Option("contract.json", "--out", "-o", help="where to write the signed contract"),
               disable: list[str] = typer.Option([], "--disable", help="guardrail id to switch off (repeatable)"),
               enable: list[str] = typer.Option([], "--enable", help="guardrail id to switch on (repeatable)"),
               yes: bool = typer.Option(False, "--yes", "-y", help="approve and sign without prompting")):
    """Draft guardrails for an AI agent (LLM-proposed), let you approve them, and write a signed contract."""
    from . import agents as agents_mod
    from . import guardrails as gr

    prop = agents_mod.propose(agent_dir, goal)
    items = prop["guardrails"]
    for it in items:
        if it["id"] in disable:
            it["enabled"] = False
        if it["id"] in enable:
            it["enabled"] = True
    rails = [g.to_dict() for g in gr.normalize(items)]
    t = Table(title=f"Proposed guardrails for {prop['agent']}", expand=True)
    for c in ("", "Guardrail", "Setting", "Why"):
        t.add_column(c, overflow="fold")
    for g in rails:
        setting = ", ".join(f"{k}={v}" for k, v in g["params"].items()) or ""
        t.add_row("[green]✓[/]" if g["enabled"] else "[dim]·[/]", f"{g['title']} [dim]({g['id']})[/]", setting, g["why"])
    console.print(f"[dim]Goal:[/] {prop['goal']}")
    console.print(t)
    console.print(f"[dim]Drafted by {prop['source']} (advisory). Checking is deterministic; the sandbox has no network "
                  f"regardless of these settings.[/]")
    if not yes and not typer.confirm("Approve and sign this contract?", default=True):
        raise typer.Exit(1)
    contract = gr.sign(prop["agent"], prop["code_hash"], rails)
    with open(out, "w") as f:
        json.dump(contract, f, indent=2)
    console.print(f"[green]Signed contract written to {out}[/] (any edit, or any change to the agent's code, voids it)")


@app.command("run")
def run_agent_cmd(agent_dir: str = typer.Argument(..., help="folder with the agent's code"),
                  contract: str = typer.Option("contract.json", "--contract", "-c"),
                  as_json: bool = typer.Option(False, "--json")):
    """Run an AI agent in the hardened sandbox and check it against its signed guardrail contract."""
    from . import agents as agents_mod

    try:
        with open(contract) as f:
            c = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Can't read contract {contract}: {e}[/]. Create one with `modelgate guardrails {agent_dir}`.")
        raise typer.Exit(2)
    r = agents_mod.run(agent_dir, c)
    if as_json:
        print(json.dumps(r, indent=2, default=str))
        raise typer.Exit(0 if r["verdict"] == "ALLOW" else 1)
    v = "BLOCK" if r["verdict"] == "BLOCK" else "ALLOW"
    label = {"BLOCK": "GUARDRAILS VIOLATED", "ALLOW": "WITHIN GUARDRAILS"}[v]
    res = r.get("resources") or {}
    sub = (f"{r['agent']}  ·  code {r['code_hash'][:12]}  ·  {res.get('wall_s', '?')}s wall, {res.get('cpu_s', '?')}s cpu, "
           f"{res.get('max_rss_mb', '?')} MB peak")
    console.print(Panel(Text(f"\n{label}\n", justify="center", style=COLORS[v]), subtitle=sub, padding=(0, 2)))
    if r["findings"]:
        t = Table(expand=True)
        for c_ in ("Guardrail", "Where", "What happened"):
            t.add_column(c_, overflow="fold")
        for f in r["findings"]:
            t.add_row(f["rule_id"].removeprefix("GR-"), f"{f['file']}:{f['line']}" if f["line"] else f["file"], f["message"])
        console.print(t)
    else:
        console.print("[green]" + "; ".join(r["reasons"]) + "[/]")
    raise typer.Exit(0 if v == "ALLOW" else 1)


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Start the web dashboard."""
    import uvicorn

    uvicorn.run("modelgate.web.app:app", host=host, port=port)


if __name__ == "__main__":
    app()
