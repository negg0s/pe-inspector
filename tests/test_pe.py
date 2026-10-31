import json
import os

import click
from click.testing import CliRunner

from pe_inspector import core, cli


def test_load_pe(minimal_pe):
    pe = core.load_pe(minimal_pe)
    assert pe is not None
    assert pe.FILE_HEADER.NumberOfSections == 1


def test_get_info(minimal_pe):
    info = core.get_info(minimal_pe)
    assert info["number_of_sections"] == 1
    assert info["machine"] == "i386"
    assert info["subsystem"] == "WINDOWS_CUI"
    assert info["entry_point"] == "0x1000"
    assert "sha256" in info


def test_get_sections(minimal_pe):
    secs = core.get_sections(minimal_pe)
    assert len(secs) == 1
    assert secs[0]["name"] == ".text"
    assert secs[0]["virtual_size"] == 0x1000
    assert secs[0]["raw_size"] == 0x200


def test_get_imports_empty(minimal_pe):
    assert core.get_imports(minimal_pe) == []


def test_get_entropy(minimal_pe):
    ent = core.get_entropy(minimal_pe)
    assert "file_entropy" in ent
    assert len(ent["sections"]) == 1
    assert ent["sections"][0]["name"] == ".text"


def test_suspicious_flag_logic():
    assert "CreateRemoteThread" in core.SUSPICIOUS_IMPORTS
    assert "NotARealApi" not in core.SUSPICIOUS_IMPORTS


def test_cli_info(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["info", minimal_pe])
    assert res.exit_code == 0, res.output
    assert "number_of_sections: 1" in res.output


def test_cli_sections_json(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["sections", minimal_pe, "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data[0]["name"] == ".text"


def test_cli_imports(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["imports", minimal_pe])
    assert res.exit_code == 0, res.output


def test_cli_imports_suspicious(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["imports", minimal_pe, "--suspicious"])
    assert res.exit_code == 0, res.output


def test_cli_entropy(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["entropy", minimal_pe])
    assert res.exit_code == 0, res.output
    assert "file_entropy:" in res.output


def test_cli_report_formats(minimal_pe):
    runner = CliRunner()
    for fmt in ("text", "json", "markdown"):
        res = runner.invoke(cli.cli, ["report", minimal_pe, "--format", fmt])
        assert res.exit_code == 0, res.output
    # json parseable
    res = runner.invoke(cli.cli, ["report", minimal_pe, "--format", "json"])
    json.loads(res.output)


def test_missing_file():
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["info", "D:/temp/pe-inspector/nonexistent.exe"])
    assert res.exit_code != 0