"""ModelGate CLI: scan / allow / serve."""
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
    sub = f"{report['target']}  ·  rev {report.get('revision') or 'main'}  ·  code {report['code_hash'][:12]}  ·  {report['scan_seconds']}s"
    con.print(Panel(Text(f"\n{v}\n", justify="center", style=COLORS[v]), subtitle=sub, style=COLORS[v].split(" on ")[-1], padding=(0, 2)))

    if report.get("allowlisted"):
        con.print("[green]Allowlisted: repo + revision + code hash match an approved entry. Code unchanged since approval.[/]")
        return

    if sb["mode"] == "subprocess":
        con.print(Panel("[bold]NOT ISOLATED[/]: Docker unavailable. Dynamic analysis ran in a plain subprocess with a temp HOME, "
                        "scrubbed env and an audit hook that denies network/process calls. Malicious code can bypass audit hooks.",
                        style="bold red"))

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

    ev = [e for e in sb["events"] if e["event"] not in ("module.imported",)]
    if ev:
        t = Table(title=f"Sandbox timeline ({sb['mode']}{' + strace' if sb.get('strace') else ''}, status: {sb['status']})", expand=True)
        t.add_column("t (s)", justify="right", no_wrap=True)
        t.add_column("Src", no_wrap=True)
        t.add_column("Event", no_wrap=True)
        t.add_column("Where", no_wrap=True)
        t.add_column("Detail", overflow="fold")
        for e in ev[:40]:
            where = f"{e['file']}:{e['line']}" if e.get("file") else ""
            style = "red" if e["event"] in policy.NET_EVENTS | policy.PROC_EVENTS | {"env.read", "os.memfd_create", "memfd_create"} else ""
            t.add_row(f"{e['t']:.3f}", e.get("source", "audit"), Text(e["event"], style=style), where, e["detail"][:120])
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
    policy.add_to_allowlist(repo_key(target), revision, report["code_hash"], report["verdict"])
    console.print(f"[green]Allowlisted {target} @ {revision or 'main'} (code hash {report['code_hash'][:12]}, "
                  f"verdict was {report['verdict']}).[/] Stored in {policy.allowlist_path()}")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Start the web dashboard."""
    import uvicorn

    uvicorn.run("modelgate.web.app:app", host=host, port=port)


if __name__ == "__main__":
    app()
