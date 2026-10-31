"""Command-line interface for pe-inspector."""

import json
import sys

import click

from . import core

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


class PeGroup(click.Group):
    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (OSError, ValueError) as exc:
            raise click.ClickException(str(exc))


@click.group(cls=PeGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option()
def cli():
    """Inspect Windows PE (Portable Executable) files."""


def _json(data):
    click.echo(json.dumps(data, indent=2))


def _file_argument():
    return click.argument("file", type=click.Path(exists=True, dir_okay=False))


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def info(file, as_json):
    """Show general information about a PE file."""
    data = core.get_info(file)
    if as_json:
        _json(data)
        return
    for key, value in data.items():
        click.echo(f"{key}: {value}")


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def headers(file, as_json):
    """Show COFF and optional header fields."""
    data = core.get_headers(file)
    if as_json:
        _json(data)
        return
    click.echo(f"file:                  {data['file']}")
    click.echo(f"size:                  {data['size']} bytes")
    click.echo(f"machine:               {data['machine']} ({data['machine_raw']})")
    click.echo(f"kind:                  {'DLL' if data['is_dll'] else 'EXE'}, "
               f"{'64-bit' if data['is_64bit'] else '32-bit'}")
    click.echo(f"subsystem:             {data['subsystem']} ({data['subsystem_raw']})")
    click.echo(f"dll_characteristics:   {data['dll_characteristics']}")
    click.echo(f"  flags:               {', '.join(data['dll_characteristics_flags']) or 'none'}")
    click.echo(f"compile_time:          {data['compile_time']} ({data['compile_time_utc'] or 'no timestamp'})")
    click.echo(f"entry_point:           {data['entry_point']}")
    click.echo(f"image_base:            {data['image_base']}")
    click.echo(f"checksum stored:       {data['checksum_stored']}")
    click.echo(f"checksum computed:     {data['checksum_computed']}")
    click.echo(f"checksum matches:      {'yes' if data['checksum_matches'] else 'no'}")
    click.echo(f"number_of_sections:    {data['number_of_sections']}")
    click.echo(f"size_of_image:         {data['size_of_image']}")
    click.echo(f"size_of_headers:       {data['size_of_headers']}")
    click.echo(f"section_alignment:     {data['section_alignment']}")
    click.echo(f"file_alignment:        {data['file_alignment']}")


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def sections(file, as_json):
    """List sections of a PE file."""
    data = core.get_sections(file)
    if as_json:
        _json(data)
        return
    click.echo(f"{'Name':<12}{'VirtualAddr':<14}{'VirtualSize':<12}{'RawSize':<10}{'Entropy':<8}Flags")
    for s in data:
        flags = "".join(
            [c for c, on in (("R", True), ("W", s["writable"]), ("X", s["executable"])) if on]
        )
        click.echo(
            f"{s['name']:<12}{s['virtual_address']:<14}{s['virtual_size']:<12}"
            f"{s['raw_size']:<10}{s['entropy']:<8}{flags}"
        )


@cli.command()
@_file_argument()
@click.option("--suspicious", is_flag=True, help="Show only suspicious imports.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def imports(file, suspicious, as_json):
    """List imported functions of a PE file."""
    data = core.get_imports(file, suspicious=suspicious)
    if as_json:
        _json(data)
        return
    if not data:
        click.echo("No imports found." if not suspicious else "No suspicious imports found.")
        return
    for imp in data:
        flag = " [SUSPICIOUS]" if imp["suspicious"] else ""
        click.echo(f"{imp['dll']}!{imp['name']}{flag}")


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def exports(file, as_json):
    """List exported functions of a PE file."""
    data = core.get_exports(file)
    if as_json:
        _json(data)
        return
    if not data["exports"]:
        click.echo("No exports found.")
        return
    click.echo(f"DLL: {data['dll_name'] or '(no name)'}")
    click.echo(f"{'Ordinal':<10}{'RVA':<12}{'Name':<32}Forwarder")
    for exp in data["exports"]:
        click.echo(
            f"{exp['ordinal']:<10}{exp['rva']:<12}"
            f"{exp['name'] or '(by ordinal)':<32}{exp['forwarder'] or ''}"
        )


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def resources(file, as_json):
    """Count resource types in a PE file."""
    data = core.get_resources(file)
    if as_json:
        _json(data)
        return
    if not data["types"]:
        click.echo("No resources found.")
        return
    click.echo(f"{'Type':<18}{'Count':<8}{'Bytes'}")
    for item in data["types"]:
        click.echo(f"{item['type']:<18}{item['count']:<8}{item['size']}")
    click.echo(f"{'TOTAL':<18}{data['total']:<8}")


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def version(file, as_json):
    """Show VERSIONINFO resource fields."""
    data = core.get_version(file)
    if as_json:
        _json(data)
        return
    if not data["present"]:
        click.echo("No version information found.")
        return
    if data["fixed"]:
        for key, value in data["fixed"].items():
            click.echo(f"{key}: {value}")
    for key, value in data["strings"].items():
        click.echo(f"{key}: {value}")


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def overlay(file, as_json):
    """Show data appended after the last section."""
    data = core.get_overlay(file)
    if as_json:
        _json(data)
        return
    if not data["present"]:
        click.echo("No overlay data.")
        return
    click.echo(f"overlay_offset: {data['offset']} (0x{data['offset']:x})")
    click.echo(f"overlay_size: {data['size']} bytes ({data['percent']}% of file)")
    click.echo(f"contains_signature: {'yes' if data['contains_signature'] else 'no'}")


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def signature(file, as_json):
    """Report Authenticode signature presence. Does not validate the chain."""
    data = core.get_signature(file)
    if as_json:
        _json(data)
        return
    click.echo(f"present: {'yes' if data['present'] else 'no'}")
    if data["present"]:
        click.echo(f"offset: {data['offset']} (0x{data['offset']:x})")
        click.echo(f"size: {data['size']} bytes")
        click.echo(f"certificate_length: {data['certificate_length']}")
        click.echo(f"revision: {data['revision']}")
        click.echo(f"certificate_type: {data['certificate_type']}")
    click.echo("validation: not performed")


@cli.command()
@_file_argument()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def scan(file, as_json):
    """Score a PE file using simple static risk indicators."""
    data = core.scan(file)
    if as_json:
        _json(data)
        return
    click.echo(f"score: {data['score']}/100 ({data['level']})")
    click.echo(data["disclaimer"])
    if not data["reasons"]:
        click.echo("No indicators matched.")
        return
    for reason in data["reasons"]:
        click.echo(f"- [{reason['weight']}] {reason['detail']}")


@cli.command()
@_file_argument()
def entropy(file):
    """Show entropy information for a PE file."""
    data = core.get_entropy(file)
    click.echo(f"file_entropy: {data['file_entropy']}")
    for s in data["sections"]:
        click.echo(f"{s['name']}: {s['entropy']}")


@cli.command()
@_file_argument()
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "markdown"]),
    default="text",
    help="Output format.",
)
def report(file, fmt):
    """Generate a report for a PE file."""
    click.echo(core.generate_report(file, fmt=fmt))


def main():
    cli()


if __name__ == "__main__":
    sys.exit(main())
