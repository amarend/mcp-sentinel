import typer
from rich.console import Console

from .repository import Repository
from .scanner import discover_files
from .detector.detector import detect_mcp
from .rules import RULES, run_security_rules


app = typer.Typer(
    help="MCP Sentinel - Analyze and audit Model Context Protocol (MCP) servers."
)

console = Console()


def print_banner():
    """Print the MCP Sentinel banner."""
    console.print("[bold green]MCP Sentinel[/bold green]")
    console.print("[dim]Analyze and audit MCP servers[/dim]\n")


@app.command()
def scan(path: str):
    """
    Scan a repository for MCP server implementation and security issues.
    """

    # ---------------------------------------------------------
    # Banner
    # ---------------------------------------------------------

    print_banner()

    console.print(f"[dim]Scanning:[/dim] {path}\n")

    # ---------------------------------------------------------
    # Step 1: Discover source files
    # ---------------------------------------------------------

    files = discover_files(path)

    console.print(
        f"[dim]Found {len(files)} source files[/dim]\n"
    )

    # ---------------------------------------------------------
    # Step 2: Create repository object
    # ---------------------------------------------------------

    repository = Repository(
        root=path,
        files=files,
    )

    # ---------------------------------------------------------
    # Step 3: Detect MCP server
    # ---------------------------------------------------------

    result = detect_mcp(repository)

    console.print("[bold]MCP Detection[/bold]")
    console.rule()

    if result.detected:

        console.print(
            "[green]✓ MCP Server Detected[/green]\n"
        )

        console.print(
            f"Language     : {result.language}"
        )

        console.print(
            f"Framework    : {result.framework}"
        )

        console.print(
            f"Confidence   : {result.confidence}"
        )

    else:

        console.print(
            "[yellow]⚠ No MCP server detected[/yellow]"
        )

    # ---------------------------------------------------------
    # Step 4: Run security rules
    # ---------------------------------------------------------

    findings = run_security_rules(files)

    # ---------------------------------------------------------
    # Step 5: Display security findings
    # ---------------------------------------------------------

    console.print("\n[bold]Security Findings[/bold]")
    console.rule()

    if findings:

        console.print(
            f"[red]Found {len(findings)} security issue(s)[/red]\n"
        )

        for finding in findings:

            severity = finding.severity.upper()

            # Choose display style based on severity
            if severity == "CRITICAL":
                severity_style = "bold red"
            elif severity == "HIGH":
                severity_style = "bold yellow"
            elif severity == "MEDIUM":
                severity_style = "bold blue"
            else:
                severity_style = "bold white"

            console.print(
                f"[{severity_style}]{severity}[/{severity_style}] "
                f"[bold]{finding.rule_id}[/bold] "
                f"{finding.title}"
            )

            console.print(
                f"File           : {finding.file}"
            )

            console.print(
                f"Description    : {finding.description}"
            )

            console.print(
                f"Recommendation : {finding.recommendation}\n"
            )

    else:

        console.print(
            "[green]✓ No security findings detected[/green]"
        )

    # ---------------------------------------------------------
    # Step 6: Security summary
    # ---------------------------------------------------------

    console.print("\n[bold]Summary[/bold]")
    console.rule()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:

        severity = finding.severity.upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    console.print(
        f"Rules Run       : {len(RULES)}"
    )

    console.print(
        f"Total Findings  : {len(findings)}"
    )

    console.print(
        f"CRITICAL        : {severity_counts['CRITICAL']}"
    )

    console.print(
        f"HIGH            : {severity_counts['HIGH']}"
    )

    console.print(
        f"MEDIUM          : {severity_counts['MEDIUM']}"
    )

    console.print(
        f"LOW             : {severity_counts['LOW']}"
    )


@app.command(
    help="Display the current MCP Sentinel version."
)
def version():
    """Print the current version."""
    typer.echo("MCP Sentinel v0.2.0")


if __name__ == "__main__":
    app()