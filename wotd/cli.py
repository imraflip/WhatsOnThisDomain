from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(
    name="wotd",
    help="Recon and attack surface monitoring pipeline for bug bounty and authorized pentesting.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def subdomains(
    target: str = typer.Argument(..., help="Target domain (e.g. acme.com or *.acme.com)"),
) -> None:
    """Run subdomain enumeration against a target."""
    console.print(f"[yellow]subdomains module not implemented yet[/yellow] (target: {target})")
    raise typer.Exit(code=1)


@app.command()
def crawl(
    url: str = typer.Argument(..., help="Full URL including scheme (e.g. https://acme.com)"),
) -> None:
    """Run endpoint discovery against a target URL."""
    if "://" not in url:
        console.print(
            "[red]error:[/red] crawl requires a full URL with scheme (e.g. https://acme.com)"
        )
        raise typer.Exit(code=2)
    console.print(f"[yellow]crawl module not implemented yet[/yellow] (url: {url})")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
