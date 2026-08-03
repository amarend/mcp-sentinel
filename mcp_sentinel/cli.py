import time
from pathlib import Path
from typing_extensions import Annotated

import typer
from rich.console import Console

from .repository import Repository
from .scanner import discover_files


app = typer.Typer(
    help="MCP Sentinel - Analyze and audit Model Context Protocol (MCP) servers."
)

console = Console()


def print_banner():
    """Print the MCP Sentinel banner."""
    console.print("[bold green]MCP Sentinel[/bold green]")
    console.print("[dim]Analyze and audit MCP servers[/dim]\n")


@app.command(help="Scan an MCP server repository.")
def scan(
    path: Annotated[
        str,
        typer.Argument(help="Path to the MCP server repository"),
    ]
):
    """Scan a repository and display a basic summary."""

    print_banner()

    repo_path = Path(path)

    # Check that the path exists
    if not repo_path.exists():
        console.print(
            f"[red]✗ Directory does not exist:[/red] {repo_path}"
        )
        raise typer.Exit(code=1)

    # Check that the path is actually a directory
    if not repo_path.is_dir():
        console.print(
            f"[red]✗ Path is not a directory:[/red] {repo_path}"
        )
        raise typer.Exit(code=1)

    console.print(
        f"[cyan]Scanning:[/cyan] {repo_path.resolve()}\n"
    )

    start = time.perf_counter()

    # Discover source files
    files = discover_files(repo_path)

    # Create repository model
    repository = Repository(
        root=repo_path,
        files=files,
    )

    elapsed = time.perf_counter() - start

    # Repository summary
    console.print("[bold]Repository Summary[/bold]\n")

    console.print(
        f"Python files       {len(repository.python_files)}"
    )

    console.print(
        f"JavaScript files   {len(repository.javascript_files)}"
    )

    console.print(
        f"TypeScript files   {len(repository.typescript_files)}"
    )

    console.print(
        f"Dockerfiles        {len(repository.dockerfiles)}"
    )

    console.print(
        f"package.json       "
        f"{'✓' if repository.has_package_json else '✗'}"
    )

    console.print(
        f"requirements.txt   "
        f"{'✓' if repository.has_requirements_txt else '✗'}"
    )

    console.print(
        f"\n[green]✓[/green] Scan completed in "
        f"[bold]{elapsed:.2f}s[/bold]"
    )


@app.command(help="Display the current MCP Sentinel version.")
def version():
    """Print the current version."""
    typer.echo("MCP Sentinel v0.1.0")


if __name__ == "__main__":
    app()