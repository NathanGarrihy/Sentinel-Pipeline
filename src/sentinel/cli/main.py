from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from sentinel.cli.scan import scan
from sentinel.cli.verify_env import verify_env
from sentinel.core.config import ConfigNotFoundError, ConfigParseError, load_config
from sentinel.core.preflight import preflight_check

app = typer.Typer(name="sentinel", help="Policy-Enforced Delivery Control Plane")
console = Console(stderr=True)


@app.callback()
def _callback(
    ctx: typer.Context,
    config: Annotated[
        Path,
        typer.Option("--config", "-c", help="Path to sentinel.yaml config file."),
    ] = Path("sentinel.yaml"),
    skip_preflight: Annotated[
        bool,
        typer.Option("--skip-preflight", help="Skip tool availability checks."),
    ] = False,
) -> None:
    """Policy-Enforced Delivery Control Plane."""
    try:
        cfg = load_config(config)
    except ConfigNotFoundError:
        console.print(f"[red]Error:[/red] Config file not found: {config.resolve()}")
        raise typer.Exit(code=1) from None
    except ConfigParseError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from None

    # Store config in Typer context so subcommands can access it
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg

    if skip_preflight:
        return

    result = preflight_check(cfg)

    for tool in result.missing_optional:
        console.print(f"[yellow]Warning:[/yellow] Optional tool not found: {tool}")

    if not result.passed:
        for tool in result.missing_required:
            console.print(f"[red]Missing required tool:[/red] {tool}")
        console.print(
            "\n[red]Pre-flight failed.[/red] Install missing tools or use --skip-preflight."
        )
        raise typer.Exit(code=1)


app.command("scan")(scan)
app.command("verify-env")(verify_env)

if __name__ == "__main__":
    app()
