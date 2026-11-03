from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from .detector.detector import detect_mcp
from .findings.models import SEVERITY_ORDER
from .live.baseline import save_baseline
from .live.client import MCPClientError
from .live.runner import LiveTarget, scan_live, watch_live
from .reporting import severity_counts, should_fail, to_json, to_sarif
from .repository import Repository
from .rules import RULES, run_security_rules
from .scanner import discover_files
from .version import __version__


app = typer.Typer(
    help="MCP Sentinel - Analyze and audit Model Context Protocol (MCP) servers."
)

console = Console()
err_console = Console(stderr=True)


class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


class FailOn(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    never = "never"


SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "bold blue",
}


def print_banner():
    """Print the MCP Sentinel banner."""
    console.print("[bold green]MCP Sentinel[/bold green]")
    console.print("[dim]Analyze and audit MCP servers[/dim]\n")


def render_console(path, repository, detection, findings):
    """Render the human-readable report."""

    print_banner()

    console.print(f"[dim]Scanning:[/dim] {path}\n")

    console.print(
        f"[dim]Found {len(repository.python_files)} Python and "
        f"{len(repository.typescript_files) + len(repository.javascript_files)}"
        " TypeScript/JavaScript file(s)[/dim]"
    )

    console.print()

    # -----------------------------------------------------
    # MCP detection
    # -----------------------------------------------------

    console.print("[bold]MCP Detection[/bold]")
    console.rule()

    if detection.detected:

        console.print("[green]✓ MCP Server Detected[/green]\n")
        console.print(f"Language     : {detection.language}")
        console.print(f"Framework    : {detection.framework}")
        console.print(f"Confidence   : {detection.confidence}")

        if detection.tools:
            console.print(
                f"Tools        : {', '.join(detection.tools)}"
            )

    else:

        console.print("[yellow]⚠ No MCP server detected[/yellow]")

    # -----------------------------------------------------
    # Findings
    # -----------------------------------------------------

    console.print("\n[bold]Security Findings[/bold]")
    console.rule()

    if findings:

        console.print(
            f"[red]Found {len(findings)} security issue(s)[/red]\n"
        )

        for finding in findings:

            severity = finding.severity.upper()
            style = SEVERITY_STYLES.get(severity, "bold white")

            location = finding.file

            if finding.line:
                location += f":{finding.line}"

            console.print(
                f"[{style}]{severity}[/{style}] "
                f"[bold]{finding.rule_id}[/bold] "
                f"{finding.title}"
            )
            console.print(f"File           : {location}")

            if finding.tool:
                console.print(f"Tool           : {finding.tool}")

            console.print(f"Description    : {finding.description}")
            console.print(
                f"Recommendation : {finding.recommendation}\n"
            )

    else:

        console.print("[green]✓ No security findings detected[/green]")

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    counts = severity_counts(findings)

    console.print("\n[bold]Summary[/bold]")
    console.rule()
    console.print(f"Rules Run       : {len(RULES)}")
    console.print(f"Total Findings  : {len(findings)}")

    for severity in SEVERITY_ORDER:
        console.print(f"{severity:<16}: {counts[severity]}")


@app.command()
def scan(
    path: str,
    output_format: OutputFormat = typer.Option(
        OutputFormat.console,
        "--format",
        "-f",
        help="Report format.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to a file instead of stdout.",
    ),
    fail_on: FailOn = typer.Option(
        FailOn.never,
        "--fail-on",
        help=(
            "Exit with code 1 if any finding is at or above this "
            "severity. Use for CI gating."
        ),
    ),
    exclude: list[str] = typer.Option(
        [],
        "--exclude",
        "-x",
        help="Directory name to skip (repeatable).",
    ),
    include_tests: bool = typer.Option(
        False,
        "--include-tests",
        help="Also scan test directories (skipped by default).",
    ),
):
    """
    Scan a repository for MCP server implementation and security issues.

    Exit codes: 0 = ok, 1 = findings at/above --fail-on, 2 = usage error.
    """

    # ---------------------------------------------------------
    # Discover files
    # ---------------------------------------------------------

    try:
        files = discover_files(
            path,
            exclude=exclude,
            include_tests=include_tests,
        )
    except ValueError as error:
        err_console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=2)

    repository = Repository(root=path, files=files)

    # ---------------------------------------------------------
    # Detect + analyse
    # ---------------------------------------------------------

    detection = detect_mcp(repository)

    findings = run_security_rules(repository.files)

    # ---------------------------------------------------------
    # Report
    # ---------------------------------------------------------

    root = Path(path)

    if output_format == OutputFormat.console:

        render_console(path, repository, detection, findings)

    else:

        report = (
            to_json(findings, root=root, rules_run=len(RULES))
            if output_format == OutputFormat.json
            else to_sarif(findings, root=root)
        )

        if output:
            output.write_text(report)
            err_console.print(
                f"[dim]Wrote {output_format.value} report to "
                f"{output}[/dim]"
            )
        else:
            typer.echo(report)

    # ---------------------------------------------------------
    # Exit code
    # ---------------------------------------------------------

    if fail_on != FailOn.never and should_fail(
        findings, fail_on.value
    ):
        raise typer.Exit(code=1)


def _parse_pairs(items: list[str], separator: str, what: str) -> dict:
    """Parse ["K=V", ...] or ["Name: Value", ...] into a dict."""

    result = {}

    for item in items:

        if separator not in item:
            err_console.print(
                f"[red]Error:[/red] {what} must look like "
                f"KEY{separator}VALUE, got '{item}'"
            )
            raise typer.Exit(code=2)

        key, value = item.split(separator, 1)
        result[key.strip()] = value.strip()

    return result


def _render_live_console(result, findings, title="Live Findings"):

    snapshot = result.snapshot

    server = snapshot.server_info or {}

    console.print("[bold]Server[/bold]")
    console.rule()
    console.print(
        f"Name         : {server.get('name', '?')} "
        f"{server.get('version', '')}"
    )
    console.print(f"Transport    : {snapshot.transport}")
    console.print(f"Protocol     : {snapshot.protocol_version}")
    console.print(
        f"Tools        : {len(snapshot.tools)}  "
        f"Prompts: {len(snapshot.prompts)}  "
        f"Resources: {len(snapshot.resources)}"
    )

    for note in snapshot.notes:
        console.print(f"[yellow]⚠ {note}[/yellow]")

    console.print(f"\n[bold]{title}[/bold]")
    console.rule()

    if not findings:
        console.print("[green]✓ No findings[/green]")
        return

    console.print(f"[red]Found {len(findings)} issue(s)[/red]\n")

    for finding in findings:

        severity = finding.severity.upper()
        style = SEVERITY_STYLES.get(severity, "bold white")

        console.print(
            f"[{style}]{severity}[/{style}] "
            f"[bold]{finding.rule_id}[/bold] {finding.title}"
        )

        if finding.tool:
            console.print(f"Subject        : {finding.tool}")

        console.print(f"Description    : {finding.description}")
        console.print(f"Recommendation : {finding.recommendation}\n")


@app.command()
def live(
    command: str | None = typer.Option(
        None,
        "--command",
        "-c",
        help=(
            "Command that starts a stdio MCP server, e.g. "
            "\"npx -y @modelcontextprotocol/server-everything\". "
            "The command is executed: only scan servers you trust, "
            "ideally inside a container or VM."
        ),
    ),
    url: str | None = typer.Option(
        None,
        "--url",
        "-u",
        help="URL of a Streamable HTTP MCP server.",
    ),
    env: list[str] = typer.Option(
        [], "--env", "-e", help="KEY=VALUE for the server process (repeatable)."
    ),
    header: list[str] = typer.Option(
        [],
        "--header",
        "-H",
        help='HTTP header "Name: Value" (repeatable), e.g. Authorization.',
    ),
    inherit_env: bool = typer.Option(
        False,
        "--inherit-env",
        help=(
            "Pass your full environment to the server. By default only "
            "PATH/HOME-style variables are passed, so the server cannot "
            "read your secrets."
        ),
    ),
    timeout: float = typer.Option(
        30.0, "--timeout", help="Seconds to wait for each server response."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.console, "--format", "-f", help="Report format."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the report to a file."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.never,
        "--fail-on",
        help="Exit 1 if any finding is at or above this severity.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Compare against a saved baseline to detect changed tools.",
    ),
    save_baseline_to: Path | None = typer.Option(
        None,
        "--save-baseline",
        help="Write the server's current tool fingerprints to this file.",
    ),
    watch: float | None = typer.Option(
        None,
        "--watch",
        help="Re-scan every N seconds and report changes (Ctrl-C to stop).",
    ),
    max_runs: int | None = typer.Option(
        None, "--max-runs", help="Stop watching after N scans."
    ),
):
    """
    Inspect a RUNNING MCP server: tool descriptions, schemas, and
    transport. Detects poisoned metadata, name collisions and (with
    --baseline / --watch) tools that change after approval.

    The scan is read-only: it lists tools but never calls them.
    Exit codes: 0 = ok, 1 = findings at/above --fail-on, 2 = error.
    """

    target = LiveTarget(
        command=command,
        url=url,
        env=_parse_pairs(env, "=", "--env"),
        headers=_parse_pairs(header, ":", "--header"),
        inherit_env=inherit_env,
        timeout=timeout,
    )

    try:
        target.validate()
    except ValueError as error:
        err_console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=2)

    if command and output_format == OutputFormat.console:
        err_console.print(
            "[yellow]⚠ Starting the server command. Only scan servers "
            "you trust.[/yellow]"
        )

    # ---------------- watch mode ----------------
    if watch is not None:

        worst = {"findings": []}

        def on_result(run, result, reported):

            worst["findings"] = reported or worst["findings"]

            if output_format == OutputFormat.console:
                console.print(f"\n[dim]── scan #{run} ──[/dim]")
                _render_live_console(
                    result,
                    reported,
                    "Live Findings" if run == 1 else "Changes",
                )
            else:
                typer.echo(
                    to_json(reported, rules_run=None).replace("\n", "")
                    if output_format == OutputFormat.json
                    else to_sarif(reported)
                )

        def on_error(run, error):
            err_console.print(f"[red]scan #{run} failed:[/red] {error}")

        try:
            watch_live(
                target, watch, on_result, on_error,
                baseline_path=baseline, max_runs=max_runs,
            )
        except KeyboardInterrupt:
            pass

        if fail_on != FailOn.never and should_fail(
            worst["findings"], fail_on.value
        ):
            raise typer.Exit(code=1)

        return

    # ---------------- single scan ----------------
    try:
        result = scan_live(target, baseline)
    except (MCPClientError, ValueError) as error:
        err_console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=2)

    if save_baseline_to:
        save_baseline(save_baseline_to, result.snapshot)
        err_console.print(
            f"[dim]Saved baseline to {save_baseline_to}[/dim]"
        )

    findings = result.findings

    if output_format == OutputFormat.console:

        print_banner()
        console.print(f"[dim]Inspecting:[/dim] {target.label}\n")
        _render_live_console(result, findings)

    else:

        report = (
            to_json(findings)
            if output_format == OutputFormat.json
            else to_sarif(findings)
        )

        if output:
            output.write_text(report)
        else:
            typer.echo(report)

    if fail_on != FailOn.never and should_fail(findings, fail_on.value):
        raise typer.Exit(code=1)


@app.command(
    help="Display the current MCP Sentinel version."
)
def version():
    """Print the current version."""
    typer.echo(f"MCP Sentinel v{__version__}")


if __name__ == "__main__":
    app()
