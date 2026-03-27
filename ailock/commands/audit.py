"""ailock audit — cross-check against known-bad package database."""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import click
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ailock.core.constants import LOCKFILE_NAME, KNOWN_BAD_DB_URL
from ailock.core.lockfile import Lockfile

console = Console()

# Local known-bad database (bundled with package)
_LOCAL_DB_PATH = Path(__file__).parent.parent / "data" / "known-bad.json"


class KnownBadEntry:
    """A known-bad package version entry."""

    def __init__(self, data: Dict):
        self.package = data.get("package", "")
        self.version = data.get("version", "")
        self.hashes = data.get("hashes", [])  # Malicious SHA256 hashes
        self.severity = data.get("severity", "HIGH")
        self.cve = data.get("cve")
        self.description = data.get("description", "")
        self.reported_at = data.get("reported_at", "")
        self.references = data.get("references", [])

    def matches_lockfile_entry(self, name: str, version: str, hashes: List[str]) -> bool:
        """Check if a lockfile entry matches this known-bad entry."""
        if self.package.lower().replace("_", "-") != name.lower().replace("_", "-"):
            return False

        # Version must match
        if self.version and self.version != version:
            return False

        # If we have specific malicious hashes, check for overlap
        if self.hashes and hashes:
            bad_set = set(self.hashes)
            pkg_set = set(hashes)
            return bool(bad_set & pkg_set)

        # Version match alone is enough if no specific hashes
        return True

    def __repr__(self) -> str:
        return f"<KnownBadEntry {self.package}=={self.version} severity={self.severity}>"


def load_local_db() -> List[KnownBadEntry]:
    """Load the bundled known-bad database."""
    if not _LOCAL_DB_PATH.exists():
        return []

    with open(_LOCAL_DB_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    return [KnownBadEntry(e) for e in data.get("entries", [])]


def fetch_remote_db(url: str = KNOWN_BAD_DB_URL, timeout: int = 15) -> Optional[List[KnownBadEntry]]:
    """Fetch the latest known-bad database from the community GitHub repo."""
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "ailock/0.1.0 (https://midnightrun.ai/ailock)",
        })
        if resp.ok:
            data = resp.json()
            return [KnownBadEntry(e) for e in data.get("entries", [])]
    except Exception:
        pass
    return None


def merge_databases(
    local: List[KnownBadEntry],
    remote: Optional[List[KnownBadEntry]],
) -> List[KnownBadEntry]:
    """Merge local and remote databases, deduplicating by package+version+hash."""
    if not remote:
        return local

    seen = set()
    merged = []

    for entry in local + remote:
        key = (entry.package.lower(), entry.version, frozenset(entry.hashes))
        if key not in seen:
            seen.add(key)
            merged.append(entry)

    return merged


@click.command()
@click.option(
    "--lockfile", "-l",
    default=LOCKFILE_NAME,
    show_default=True,
    help="Path to .ailock lockfile.",
    type=click.Path(),
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Use only bundled known-bad database (no network call).",
)
@click.option(
    "--db-url",
    default=KNOWN_BAD_DB_URL,
    show_default=False,
    help="URL to known-bad JSON database.",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output results as JSON (for CI integration).",
)
@click.option(
    "--show-db",
    is_flag=True,
    default=False,
    help="Print the full known-bad database and exit.",
)
def audit(lockfile, offline, db_url, json_output, show_db):
    """Cross-check packages against known-bad versions database.

    Compares packages in .ailock against a community-maintained database of
    confirmed malicious package versions (known supply chain attacks).

    The database ships with ailock and is also fetched fresh from GitHub
    on each run (use --offline to skip the network call).

    \b
    Inaugural entries:
        litellm 1.82.7 — malicious code injected post-release
        litellm 1.82.8 — follow-on compromised release

    \b
    Examples:
        ailock audit
        ailock audit --offline
        ailock audit --show-db
        ailock audit --json-output
    """
    # Show DB mode
    if show_db:
        local = load_local_db()
        if not offline:
            remote = fetch_remote_db(db_url)
            db = merge_databases(local, remote)
        else:
            db = local

        if not db:
            console.print("[yellow]Known-bad database is empty.[/yellow]\n")
            return

        table = Table(
            title="Known-Bad Package Database",
            show_header=True,
            header_style="bold red",
            border_style="dim",
        )
        table.add_column("Package", style="red")
        table.add_column("Version", style="yellow")
        table.add_column("Severity", style="bold")
        table.add_column("CVE", style="dim")
        table.add_column("Description")

        for entry in sorted(db, key=lambda e: (e.package, e.version)):
            sev_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(
                entry.severity, "dim"
            )
            table.add_row(
                entry.package,
                entry.version,
                f"[{sev_style}]{entry.severity}[/{sev_style}]",
                entry.cve or "—",
                entry.description[:80] + ("..." if len(entry.description) > 80 else ""),
            )

        console.print(table)
        return

    if not json_output:
        console.print("\n[bold cyan]ailock audit[/bold cyan] — checking known-bad database\n")

    # Load lockfile
    try:
        lf = Lockfile.load(Path(lockfile))
    except FileNotFoundError as e:
        console.print(f"[red]✗[/red] {e}\n")
        sys.exit(1)

    # Load known-bad database
    local_db = load_local_db()
    remote_db = None

    if not offline:
        if not json_output:
            console.print("[dim]Fetching latest known-bad database...[/dim]", end=" ")
        remote_db = fetch_remote_db(db_url)
        if not json_output:
            if remote_db:
                console.print(f"[green]✓[/green] ({len(remote_db)} entries)")
            else:
                console.print(
                    "[yellow]unavailable[/yellow] [dim](using bundled DB — "
                    "remote DB could not be reached)[/dim]"
                )
    else:
        if not json_output:
            console.print(f"[dim]Using local database ({len(local_db)} entries)[/dim]")

    db = merge_databases(local_db, remote_db)

    if not db:
        if not json_output:
            console.print(
                "[yellow]⚠[/yellow]  Known-bad database is empty. "
                "Consider contributing at github.com/midnightrun-ai/ailock\n"
            )
        return

    if not json_output:
        console.print(
            f"\n[dim]Auditing {len(lf)} packages against {len(db)} known-bad entries...[/dim]\n"
        )

    # Cross-check
    hits: List[tuple] = []  # (lockfile_entry, known_bad_entry)

    for name, entry in lf.packages.items():
        for bad_entry in db:
            if bad_entry.matches_lockfile_entry(name, entry.version, entry.hashes):
                hits.append((entry, bad_entry))

    # Output results
    if json_output:
        output = {
            "lockfile": lockfile,
            "db_entries": len(db),
            "packages_checked": len(lf),
            "hits": len(hits),
            "matches": [
                {
                    "package": h[0].name,
                    "version": h[0].version,
                    "severity": h[1].severity,
                    "cve": h[1].cve,
                    "description": h[1].description,
                    "references": h[1].references,
                }
                for h in hits
            ],
        }
        import json as _json
        click.echo(_json.dumps(output, indent=2))
        if hits:
            sys.exit(1)
        return

    if hits:
        console.print()
        console.print(
            Panel(
                "\n".join([
                    "[bold red]🚨 KNOWN-BAD PACKAGES DETECTED[/bold red]\n",
                    f"[red]{len(hits)} package(s) match known supply chain attacks.[/red]",
                    "[dim]These are confirmed malicious versions. Remove them immediately.[/dim]",
                ]),
                border_style="red",
                title="[red]AUDIT FAILED[/red]",
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
        table.add_column("Severity", style="bold")
        table.add_column("CVE", style="dim")
        table.add_column("Description", style="yellow")

        for pkg_entry, bad_entry in hits:
            sev_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(
                bad_entry.severity, "dim"
            )
            table.add_row(
                pkg_entry.name,
                pkg_entry.version,
                f"[{sev_style}]{bad_entry.severity}[/{sev_style}]",
                bad_entry.cve or "—",
                bad_entry.description[:60] + ("..." if len(bad_entry.description) > 60 else ""),
            )

        console.print(table)
        console.print()

        # Show references for each hit
        for pkg_entry, bad_entry in hits:
            console.print(f"[bold red]{pkg_entry.name}=={pkg_entry.version}[/bold red]")
            console.print(f"  [dim]{bad_entry.description}[/dim]")
            if bad_entry.references:
                for ref in bad_entry.references:
                    console.print(f"  [blue underline]{ref}[/blue underline]")
            console.print()

        sys.exit(1)
    else:
        console.print(
            f"[bold green]✓  Clean[/bold green] — no known-bad packages found "
            f"(checked {len(lf)} packages against {len(db)} known-bad entries)\n"
        )
