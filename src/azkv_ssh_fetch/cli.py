"""Typer CLI: `azkv-ssh-fetch` (alias `akf`).

Subcommands:
    list      List SSH-shaped secrets in a Key Vault.
    fetch     Pull a private key from KV to a local file (chmod 600).
    connect   fetch + open Bastion SSH session in one command.

All commands accept --vault from --vault flag or AZKV_VAULT env var.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from azkv_ssh_fetch import __version__
from azkv_ssh_fetch.bastion import BastionTarget, ssh_via_bastion
from azkv_ssh_fetch.errors import AzkvSshFetchError
from azkv_ssh_fetch.keyvault import fetch_secret, list_secrets
from azkv_ssh_fetch.ssh import default_ssh_dir, write_private_key

app = typer.Typer(
    name="azkv-ssh-fetch",
    help="Fetch SSH private keys from Azure Key Vault and connect via Bastion.",
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
)
stdout = Console()
stderr = Console(stderr=True)

VaultOpt = Annotated[
    str,
    typer.Option(
        "--vault",
        "-v",
        envvar="AZKV_VAULT",
        help="Key Vault name (not full URL). Required, or set [bold]AZKV_VAULT[/bold].",
    ),
]


def _version_callback(value: bool) -> None:
    if value:
        stdout.print(f"azkv-ssh-fetch [bold cyan]{__version__}[/bold cyan]")
        raise typer.Exit()


@app.callback()
def _root(
    _version: Annotated[  # noqa: ARG001 - typer needs the param for the flag
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """Common options."""


@app.command("list")
def cmd_list(vault: VaultOpt) -> None:
    """List secrets in [bold]VAULT[/bold] that look like SSH keys."""
    try:
        secrets = list(list_secrets(vault))
    except AzkvSshFetchError as exc:
        stderr.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title=f"Secrets in {vault}", show_lines=False)
    table.add_column("Name", style="cyan")
    table.add_column("Enabled", justify="center")
    table.add_column("Content-Type", style="dim")

    shown = 0
    for s in secrets:
        if not s.enabled:
            continue
        # Best-effort filter: SSH keys are usually named *ssh*, *key*, *id_rsa*
        lower = s.name.lower()
        looks_like_key = any(tok in lower for tok in ("ssh", "key", "id_rsa", "id_ed25519"))
        if not looks_like_key:
            continue
        table.add_row(s.name, "yes", s.content_type or "")
        shown += 1

    if shown == 0:
        stderr.print(
            f"[yellow]no SSH-shaped secrets found in {vault}.[/yellow]"
            " Try [bold]az keyvault secret list[/bold] for the full list."
        )
        raise typer.Exit(code=1)
    stdout.print(table)


@app.command("fetch")
def cmd_fetch(
    vault: VaultOpt,
    secret: Annotated[str, typer.Argument(help="Secret name in the vault.")],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Destination path. Default: ~/.ssh/<secret>.",
        ),
    ] = None,
) -> None:
    """Pull [bold]SECRET[/bold] from [bold]VAULT[/bold] and write it locally (chmod 600)."""
    dest = output if output is not None else default_ssh_dir() / secret
    try:
        material = fetch_secret(vault, secret)
        written = write_private_key(material, dest)
    except AzkvSshFetchError as exc:
        stderr.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    stdout.print(f"[green]wrote[/green] {written} (mode 600)")


@app.command("connect")
def cmd_connect(
    vault: VaultOpt,
    secret: Annotated[str, typer.Option("--secret", "-s", help="KV secret name.")],
    bastion_name: Annotated[str, typer.Option("--bastion", "-b", help="Bastion name.")],
    bastion_rg: Annotated[str, typer.Option("--bastion-rg", help="Bastion's resource group.")],
    target_id: Annotated[
        str,
        typer.Option(
            "--target-id",
            "-t",
            help="Full ARM resource ID of target VM or VMSS instance.",
        ),
    ],
    username: Annotated[
        str, typer.Option("--username", "-u", help="SSH username on the target.")
    ] = "azureuser",
    keep_key: Annotated[
        bool,
        typer.Option("--keep-key/--shred-key", help="Leave the key on disk after disconnect."),
    ] = False,
) -> None:
    """Fetch private key, then SSH into target through Bastion."""
    dest = default_ssh_dir() / f"akf-{secret}"
    try:
        material = fetch_secret(vault, secret)
        key_path = write_private_key(material, dest)
        stdout.print(f"[green]\u2713[/green] key fetched to {key_path}")
        rc = ssh_via_bastion(
            BastionTarget(
                bastion_name=bastion_name,
                bastion_resource_group=bastion_rg,
                target_resource_id=target_id,
                username=username,
            ),
            key_path,
        )
    except AzkvSshFetchError as exc:
        stderr.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    finally:
        if not keep_key:
            try:
                dest.unlink(missing_ok=True)
                stdout.print(f"[dim]shredded {dest}[/dim]")
            except OSError as exc:
                stderr.print(f"[yellow]warning:[/yellow] could not remove {dest}: {exc}")

    raise typer.Exit(code=rc)


def main() -> None:
    """Entry point for `python -m azkv_ssh_fetch` and the console-script."""
    # Surface azure-identity verbose logs only when AZKV_DEBUG=1
    if os.environ.get("AZKV_DEBUG") == "1":
        import logging

        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
    app()


if __name__ == "__main__":
    main()
