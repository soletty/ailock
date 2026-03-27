"""Main CLI entry point for ailock."""

import click
from rich.console import Console

from ailock import __version__

console = Console()

BANNER = """[bold cyan]
  ██████╗ ██╗██╗      ██████╗  ██████╗██╗  ██╗
  ██╔══██╗██║██║     ██╔═══██╗██╔════╝██║ ██╔╝
  ███████║██║██║     ██║   ██║██║     █████╔╝
  ██╔══██║██║██║     ██║   ██║██║     ██╔═██╗
  ██║  ██║██║███████╗╚██████╔╝╚██████╗██║  ██╗
  ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝[/bold cyan]
[dim]  Cryptographic lockfile for AI/LLM dependencies[/dim]
"""


@click.group()
@click.version_option(version=__version__, prog_name="ailock")
def main():
    """ailock — cryptographic lockfile for AI/LLM dependencies.

    Works like package-lock.json but specifically for the AI Python
    ecosystem (litellm, langchain, openai, transformers, etc.).

    \b
    Quick start:
        ailock generate    # scan deps, write .ailock
        ailock verify      # check hashes match
        ailock audit       # check for known-bad versions

    \b
    GitHub Actions (one-liner):
        - run: pip install ailock && ailock verify && ailock audit
    """
    pass


from ailock.commands.generate import generate  # noqa: E402
from ailock.commands.verify import verify  # noqa: E402
from ailock.commands.audit import audit  # noqa: E402

main.add_command(generate)
main.add_command(verify)
main.add_command(audit)
