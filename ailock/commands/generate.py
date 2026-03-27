"""ailock generate — scan dependencies and write .ailock lockfile."""

from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import print as rprint

from ailock.core.constants import LOCKFILE_NAME
from ailock.core.lockfile import Lockfile, PackageEntry
from ailock.core.pypi import get_hashes, PyPIError
from ailock.core.resolver import (
    discover_source_files,
    parse_source_file,
    filter_ai_packages,
    get_installed_packages,
    ParsedPackage,
)

console = Console()


@click.command()
@click.option(
    "--output", "-o",
    default=LOCKFILE_NAME,
    show_default=True,
    help="Output lockfile path.",
    type=click.Path(),
)
@click.option(
    "--all-packages", "-a",
    is_flag=True,
    default=False,
    help="Include ALL packages (not just AI/LLM ecosystem packages).",
)
@click.option(
    "--from-installed", "-i",
    is_flag=True,
    default=False,
    help="Use currently installed package versions instead of requirements files.",
)
@click.option(
    "--file", "-f",
    multiple=True,
    help="Specific requirements file(s) to scan (can be repeated).",
    type=click.Path(exists=True),
)
@click.option(
    "--no-hashes",
    is_flag=True,
    default=False,
    help="Skip PyPI hash fetching (faster but less secure).",
)
def generate(output, all_packages, from_installed, file, no_hashes):
    """Scan AI/LLM dependencies and write a cryptographic lockfile.

    Reads requirements.txt and/or pyproject.toml, resolves all AI/LLM
    dependencies, fetches SHA256 hashes from PyPI for each pinned version,
    and writes an .ailock file.

    \b
    Examples:
        ailock generate
        ailock generate --all-packages
        ailock generate --from-installed
        ailock generate -f requirements-prod.txt -f requirements-dev.txt
    """
    console.print("\n[bold cyan]ailock generate[/bold cyan] — scanning dependencies\n")

    lockfile = Lockfile()
    packages_to_process: List[ParsedPackage] = []

    # --- Discover packages ---
    if from_installed:
        console.print("[dim]Mode: installed packages[/dim]")
        installed = get_installed_packages()

        if not installed:
            console.print("[yellow]Warning: No installed packages found.[/yellow]")
            return

        for name, version in installed.items():
            pkg = ParsedPackage(name=name, version=version, source_file="<installed>")
            packages_to_process.append(pkg)

        lockfile.source_files = ["<installed>"]
    else:
        # Determine source files
        source_paths = []
        if file:
            source_paths = [Path(f) for f in file]
        else:
            source_paths = discover_source_files()

        if not source_paths:
            console.print(
                "[red]✗[/red] No requirements files found. "
                "Create requirements.txt or pyproject.toml, or use --from-installed.\n"
            )
            raise click.Abort()

        console.print(f"[dim]Found source files:[/dim]")
        for p in source_paths:
            console.print(f"  [cyan]→[/cyan] {p}")
        console.print()

        for p in source_paths:
            pkgs = parse_source_file(p)
            packages_to_process.extend(pkgs)
            lockfile.source_files.append(str(p))

        # Deduplicate by name (keep last occurrence)
        seen = {}
        for pkg in packages_to_process:
            seen[pkg.name] = pkg
        packages_to_process = list(seen.values())

    # --- Filter to AI/LLM packages ---
    if not all_packages:
        ai_pkgs = filter_ai_packages(packages_to_process, ai_only=True)
        other_count = len(packages_to_process) - len(ai_pkgs)
        packages_to_process = ai_pkgs

        if other_count > 0:
            console.print(
                f"[dim]Filtered to AI/LLM ecosystem packages "
                f"({other_count} non-AI packages skipped). "
                f"Use --all-packages to include everything.[/dim]\n"
            )

    if not packages_to_process:
        console.print(
            "[yellow]No AI/LLM packages found.[/yellow] "
            "Use --all-packages to include all packages.\n"
        )
        return

    console.print(f"Found [bold]{len(packages_to_process)}[/bold] packages to lock.\n")

    # --- Skip packages without pinned versions ---
    unpinned = [p for p in packages_to_process if not p.version]
    pinned = [p for p in packages_to_process if p.version]

    if unpinned:
        console.print(
            f"[yellow]⚠[/yellow]  {len(unpinned)} packages without pinned versions "
            f"(skipping — pin with ==version for full security):"
        )
        for p in unpinned[:10]:
            console.print(f"   [dim]{p.name}[/dim]")
        if len(unpinned) > 10:
            console.print(f"   [dim]... and {len(unpinned) - 10} more[/dim]")
        console.print()

    if not pinned:
        console.print(
            "[red]✗[/red] No pinned packages found. "
            "Pin your AI/LLM packages with exact versions (e.g., litellm==1.84.0).\n"
        )
        raise click.Abort()

    # --- Fetch hashes from PyPI ---
    if no_hashes:
        console.print("[yellow]⚠[/yellow]  Skipping hash fetching (--no-hashes).\n")
        for pkg in pinned:
            entry = PackageEntry(
                name=pkg.name,
                version=pkg.version,
                hashes=[],
                source="pypi",
            )
            lockfile.add_package(entry)
    else:
        console.print(f"[dim]Fetching SHA256 hashes from PyPI...[/dim]\n")

        success_count = 0
        error_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Fetching hashes...", total=len(pinned))

            for pkg in pinned:
                progress.update(task, description=f"[cyan]{pkg.name}[/cyan] {pkg.version}")

                try:
                    hashes = get_hashes(pkg.name, pkg.version)
                    entry = PackageEntry(
                        name=pkg.name,
                        version=pkg.version,
                        hashes=hashes,
                        source="pypi",
                    )
                    lockfile.add_package(entry)

                    if hashes:
                        success_count += 1
                    else:
                        console.print(
                            f"  [yellow]⚠[/yellow]  {pkg.name}=={pkg.version}: "
                            f"no hashes returned from PyPI"
                        )
                        success_count += 1  # Still add it

                except PyPIError as e:
                    console.print(
                        f"  [red]✗[/red]  {pkg.name}=={pkg.version}: {e}"
                    )
                    error_count += 1
                    # Add entry without hashes so it's still tracked
                    entry = PackageEntry(
                        name=pkg.name,
                        version=pkg.version,
                        hashes=[],
                        source="pypi",
                    )
                    lockfile.add_package(entry)

                progress.advance(task)

        console.print()
        if error_count:
            console.print(
                f"[yellow]⚠[/yellow]  {success_count} packages locked, "
                f"{error_count} failed to fetch hashes.\n"
            )
        else:
            console.print(
                f"[green]✓[/green]  {success_count} packages locked successfully.\n"
            )

    # --- Write lockfile ---
    output_path = Path(output)
    written = lockfile.write(output_path)

    console.print(
        f"[bold green]✓[/bold green] Wrote [bold]{written}[/bold] "
        f"({len(lockfile)} packages locked)\n"
    )

    # --- Summary table ---
    if len(lockfile) <= 20:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            box=None,
        )
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="white")
        table.add_column("Hashes", style="dim")

        for name, entry in sorted(lockfile.packages.items()):
            table.add_row(
                name,
                entry.version,
                str(len(entry.hashes)),
            )

        console.print(table)
        console.print()

    console.print(
        "[dim]Commit .ailock to version control. "
        "Run 'ailock verify' in CI to catch tampering.[/dim]\n"
    )
