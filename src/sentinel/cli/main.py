import typer

from sentinel.cli.verify_env import verify_env

app = typer.Typer(name="sentinel", help="Policy-Enforced Delivery Control Plane")


@app.callback()
def _callback() -> None:
    """Policy-Enforced Delivery Control Plane."""


app.command("verify-env")(verify_env)

if __name__ == "__main__":
    app()
