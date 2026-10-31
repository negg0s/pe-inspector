"""Command-line interface for pe-inspector."""

import json
import sys

import click

from . import core

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option()
def cli():
    """Inspect Windows PE (Portable Executable) files."""


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
def info(file):
    """Show general information about a PE file."""
    data = core.get_info(file)
    for key, value in data.items():
        click.echo(f"{key}: {value}")


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def sections(file, as_json):
    """List sections of a PE file."""
    data = core.get_sections(file)
    if as_json:
        click.echo(json.dumps(data, indent=2))
        return
    click.echo(f"{'Name':<12}{'VirtualAddr':<14}{'VirtualSize':<12}{'RawSize':<10}{'Entropy':<8}")
    for s in data:
        click.echo(
            f"{s['name']:<12}{s['virtual_address']:<14}{s['virtual_size']:<12}"
            f"{s['raw_size']:<10}{s['entropy']:<8}"
        )


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--suspicious", is_flag=True, help="Show only suspicious imports.")
def imports(file, suspicious):
    """List imported functions of a PE file."""
    data = core.get_imports(file, suspicious=suspicious)
    if not data:
        click.echo("No imports found." if not suspicious else "No suspicious imports found.")
        return
    for imp in data:
        flag = " [SUSPICIOUS]" if imp["suspicious"] else ""
        click.echo(f"{imp['dll']}!{imp['name']}{flag}")


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
def entropy(file):
    """Show entropy information for a PE file."""
    data = core.get_entropy(file)
    click.echo(f"file_entropy: {data['file_entropy']}")
    for s in data["sections"]:
        click.echo(f"{s['name']}: {s['entropy']}")


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["text", "json", "markdown"]), default="text", help="Output format.")
def report(file, fmt):
    """Generate a report for a PE file."""
    out = core.generate_report(file, fmt=fmt)
    click.echo(out)


def main():
    cli()


if __name__ == "__main__":
    main()