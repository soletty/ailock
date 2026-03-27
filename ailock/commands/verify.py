"""ailock verify — check installed packages against .ailock hashes."""

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from ailock.core.constants import LOCKFILE_NAME
from ailock.core.lockfile import Lockfile, PackageEntry
from ailock.core.pypi import get_hashes, PyPIError

console = Console()


class VerifyResult:
    """Result of verifying a single package."""

    OK = "ok"
    TAMPERED = "tampered"
    MISSING = "missing"
    NO_HASHES = "no_hashes"
    ERROR = "error"

    def __init__(
        self,
        name: str,
        version: str,
        status: str,
        expected_hashes: List[str],
        actual_hashes: List[str],
        message: str = "",
    ):
        self.name = name
        self.version = version
        self.status = status
        self.expected_hashes = expected_hashes
        self.actual_hashes = actual_hashes
        self.message = message

    @property
    def is_ok(self) -> bool:
        return self.status == self.OK

    @property
    def is_tampered(self) -> bool:
        return self.status == self.TAMPERED


def verify_package(entry: PackageEntry) -> VerifyResult:
    """
    Verify a single package by re-fetching its hashes from PyPI.

    The key insight: if the hashes on PyPI changed since we generated the
    lockfile, that means the package was replaced/modified after release.
    This is exactly what happened with LiteLLM v1.82.7/v1.82.8.
    """
    if not entry.hashes:
        return VerifyResult(
            name=entry.name,
            version=entry.version,
            status=VerifyResult.NO_HASHES,
            expected_hashes=[],
            actual_hashes=[],
            message="No hashes in lockfile — regenerate with 'ailock generate'",
        )

    try:
        current_hashes = get_hashes(entry.name, entry.version)
    except PyPIError as e:
        return VerifyResult(
            name=entry.name,
            version=entry.version,
            status=VerifyResult.ERROR,
            expected_hashes=entry.hashes,
            actual_hashes=[],
            message=str(e),
        )

    if not current_hashes:
        return VerifyResult(
            name=entry.name,
            version=entry.version,
            status=VerifyResult.MISSING,
            expected_hashes=entry.hashes,
            actual_hashes=[],
            message="Package version not found on PyPI (yanked or removed?)",
        )

    # Compare hash sets — ANY mismatch is a red flag
    expected_set = set(entry.hashes)
    actual_set = set(current_hashes)

    if expected_set == actual_set:
        return VerifyResult(
            name=entry.name,
            version=entry.version,
            status=VerifyResult.OK,
            expected_hashes=entry.hashes,
            actual_hashes=current_hashes,
        )

    # Hashes changed! This is the attack detection.
    new_hashes = actual_set - expected_set
    removed_hashes = expected_set - actual_set

    msg_parts = []
    if new_hashes:
        msg_parts.append(f"{len(new_hashes)} new hash(es) added after lockfile was generated")
    if removed_hashes:
        msg_parts.append(f"{len(removed_hashes)} hash(es) removed")

    return VerifyResult(
        name=entry.name,
        version=entry.version,
        status=VerifyResult.TAMPERED,
        expected_hashes=entry.hashes,
        actual_hashes=current_hashes,
        message="; ".join(msg_parts),
    )


@click.command()
@click.option(
    "--lockfile", "-l",
    default=LOCKFILE_NAME,
    show_default=True,
    help="Path to .ailock lockfile.",
    type=click.Path(),
)
@click.option(
    "--fail-on-missing",
    is_flag=True,
    default=False,
    help="Exit with error if any package from lockfile is not on PyPI.",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output results as JSON (for CI integration).",
)
def verify(lockfile, fail_on_missing, json_output):
    """Verify installed packages against .ailock cryptographic hashes.

    Re-fetches SHA256 hashes from PyPI for every package in .ailock and
    compares against stored values. If ANY hash changed since the lockfile
    was generated, that package has been tampered with.

    This is how ailock would have caught the LiteLLM v1.82.7/v1.82.8
    supply chain attack: the hash changed mid-version after the initial
    release.

    IMPORTANT LIMITATION: verify compares your lockfile hashes against the
    CURRENT state of PyPI. If an attack occurred and PyPI has since been
    cleaned up (the malicious files replaced again with clean ones), verify
    will show 'OK' — it cannot retroactively detect attacks that predate
    your lockfile. For detecting known historically-compromised versions, use
    'ailock audit' which checks against the known-bad database regardless of
    current PyPI state.

    \b
    Examples:
        ailock verify
        ailock verify --fail-on-missing
        ailock verify --json-output
    """
    if not json_output:
        console.print("\n[bold cyan]ailock verify[/bold cyan] — checking integrity\n")
        console.print(
            "[dim]Note: verify detects changes since your lockfile was generated. "
            "For historically-known attacks, also run [bold]ailock audit[/bold].[/dim]\n"
        )

    # Load lockfile
    try:
        lf = Lockfile.load(Path(lockfile))
    except FileNotFoundError as e:
        console.print(f"[red]✗[/red] {e}\n")
        sys.exit(1)

    if not lf.packages:
        console.print("[yellow]Warning: Lockfile is empty.[/yellow]\n")
        return

    if not json_output:
        console.print(
            f"[dim]Loaded [bold]{len(lf)}[/bold] packages from [bold]{lockfile}[/bold] "
            f"(generated {lf.generated_at or 'unknown'})[/dim]\n"
        )

    # Verify each package
    results: List[VerifyResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        disable=json_output,
    ) as progress:
        task = progress.add_task("Verifying...", total=len(lf.packages))

        for name, entry in sorted(lf.packages.items()):
            progress.update(task, description=f"[cyan]{name}[/cyan] {entry.version}")
            result = verify_package(entry)
            results.append(result)
            progress.advance(task)

    # Output results
    if json_output:
        import json

        output = {
            "lockfile": lockfile,
            "generated_at": lf.generated_at,
            "total": len(results),
            "ok": sum(1 for r in results if r.status == VerifyResult.OK),
            "tampered": sum(1 for r in results if r.is_tampered),
            "errors": sum(1 for r in results if r.status == VerifyResult.ERROR),
            "packages": [
                {
                    "name": r.name,
                    "version": r.version,
                    "status": r.status,
                    "message": r.message,
                }
                for r in results
            ],
        }
        import json as _json
        click.echo(_json.dumps(output, indent=2))
        tampered = [r for r in results if r.is_tampered]
        if tampered:
            sys.exit(1)
        return

    console.print()

    # Categorise results
    ok = [r for r in results if r.status == VerifyResult.OK]
    tampered = [r for r in results if r.is_tampered]
    no_hashes = [r for r in results if r.status == VerifyResult.NO_HASHES]
    missing = [r for r in results if r.status == VerifyResult.MISSING]
    errors = [r for r in results if r.status == VerifyResult.ERROR]

    # Show tampered packages prominently
    if tampered:
        console.print()
        console.print(
            Panel(
                "\n".join([
                    f"[bold red]🚨 SUPPLY CHAIN ATTACK DETECTED[/bold red]\n",
                    f"[red]{len(tampered)} package(s) have been modified since your lockfile was generated.[/red]",
                    "[dim]This means the package was replaced on PyPI after you pinned it.[/dim]",
                    "[dim]DO NOT deploy. Investigate immediately.[/dim]",
                ]),
                border_style="red",
                title="[red]INTEGRITY VIOLATION[/red]",
            )
        )
        console.print()

        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="red",
        )
        table.add_column("Package", style="red bold")
        table.add_column("Version", style="red")
        table.add_column("Issue", style="yellow")

        for r in tampered:
            table.add_row(r.name, r.version, r.message)

        console.print(table)
        console.print()

        # Show hash diff for each tampered package
        for r in tampered:
            console.print(f"[bold red]{r.name}=={r.version}[/bold red]")
            expected = set(r.expected_hashes)
            actual = set(r.actual_hashes)

            for h in sorted(expected - actual):
                console.print(f"  [red]- {h[:40]}...[/red]  [dim](in lockfile, removed from PyPI)[/dim]")
            for h in sorted(actual - expected):
                console.print(f"  [red]+ {h[:40]}...[/red]  [dim](new on PyPI, not in lockfile)[/dim]")
            console.print()

    # Show errors/warnings
    if missing and fail_on_missing:
        console.print("[yellow]⚠  Packages not found on PyPI:[/yellow]")
        for r in missing:
            console.print(f"   {r.name}=={r.version}: {r.message}")
        console.print()

    if errors:
        console.print("[yellow]⚠  Packages with fetch errors:[/yellow]")
        for r in errors:
            console.print(f"   {r.name}=={r.version}: {r.message}")
        console.print()

    # Summary
    if not tampered:
        console.print(
            f"[bold green]✓  All {len(ok)} packages verified — integrity intact[/bold green]\n"
        )
    else:
        console.print(
            f"[bold red]✗  {len(tampered)} tampered, {len(ok)} clean[/bold red]\n"
        )

    if no_hashes:
        console.print(
            f"[dim]{len(no_hashes)} packages skipped (no hashes in lockfile — "
            f"regenerate to add them)[/dim]\n"
        )

    # Exit with non-zero if tampered or (missing and fail-on-missing)
    if tampered or (missing and fail_on_missing):
        sys.exit(1)
