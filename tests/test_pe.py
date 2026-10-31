import json
import gc
import os
import subprocess
import sys
import uuid

import pytest
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
    assert len(info["sha256"]) == 64


def test_get_headers(minimal_pe):
    data = core.get_headers(minimal_pe)
    assert data["machine"] == "i386"
    assert data["subsystem"] == "WINDOWS_CUI"
    assert data["compile_time"] == 1600000000
    assert data["compile_time_utc"] == "2020-09-13T12:26:40Z"
    assert data["entry_point"] == "0x1000"
    assert data["image_base"] == "0x400000"
    assert data["checksum_matches"] is True
    assert data["dll_characteristics_flags"] == ["DYNAMIC_BASE", "NX_COMPAT"]


def test_get_sections(minimal_pe):
    secs = core.get_sections(minimal_pe)
    assert len(secs) == 1
    assert secs[0]["name"] == ".text"
    assert secs[0]["virtual_size"] == 0x1000
    assert secs[0]["raw_size"] == 0x200
    assert secs[0]["executable"] is True
    assert secs[0]["writable"] is False


def test_get_imports(imports_pe):
    data = core.get_imports(imports_pe)
    assert len(data) == 5
    names = {item["name"] for item in data}
    assert "CreateRemoteThread" in names
    suspicious = core.get_imports(imports_pe, suspicious=True)
    assert len(suspicious) == 4


def test_get_imports_empty(minimal_pe):
    assert core.get_imports(minimal_pe) == []


def test_get_exports(exports_pe):
    data = core.get_exports(exports_pe)
    assert data["dll_name"] == os.path.basename(exports_pe)
    assert [item["name"] for item in data["exports"]] == ["Alpha", "Beta", "Gamma"]
    assert data["exports"][0]["ordinal"] == 1
    assert data["exports"][0]["rva"] == "0x1000"


def test_get_exports_empty(minimal_pe):
    data = core.get_exports(minimal_pe)
    assert data["exports"] == []


def test_get_resources(resources_pe):
    data = core.get_resources(resources_pe)
    assert data["total"] == 3
    types = {item["type"]: item for item in data["types"]}
    assert types["RT_ICON"]["count"] == 2
    assert types["RT_RCDATA"]["count"] == 1


def test_get_resources_empty(minimal_pe):
    data = core.get_resources(minimal_pe)
    assert data["total"] == 0
    assert data["types"] == []


def test_get_version(version_pe):
    data = core.get_version(version_pe)
    assert data["present"] is True
    assert data["fixed"]["file_version"] == "1.2.3.4"
    assert data["strings"]["CompanyName"] == "Acme Tools"
    assert data["strings"]["ProductName"] == "Fixture"


def test_get_version_empty(minimal_pe):
    data = core.get_version(minimal_pe)
    assert data["present"] is False
    assert data["strings"] == {}


def test_get_entropy(minimal_pe):
    ent = core.get_entropy(minimal_pe)
    assert "file_entropy" in ent
    assert len(ent["sections"]) == 1
    assert ent["sections"][0]["name"] == ".text"


def test_get_overlay(overlay_pe, minimal_pe):
    data = core.get_overlay(overlay_pe)
    assert data["present"] is True
    assert data["size"] == len(b"OVERLAY" * 64)
    assert data["offset"] > 0
    assert data["contains_signature"] is False
    assert core.get_overlay(minimal_pe)["present"] is False


def test_get_signature(signature_pe, minimal_pe):
    data = core.get_signature(signature_pe)
    assert data["present"] is True
    assert data["valid"] is False
    assert data["validation_performed"] is False
    assert data["certificate_type"] == "PKCS_SIGNED_DATA"
    assert data["revision"] == "0x200"
    assert data["offset"] % 8 == 0
    assert core.get_signature(minimal_pe)["present"] is False


def test_get_signature_rejects_out_of_file_directory(minimal_pe):
    # The security directory is a file offset, unlike other PE directories.
    with open(minimal_pe, "r+b") as fh:
        fh.seek(0x40 + 4 + 20 + 96 + 4 * 8)
        fh.write((0x7FFFFFF0).to_bytes(4, "little"))
        fh.write((8).to_bytes(4, "little"))
    data = core.get_signature(minimal_pe)
    assert data["present"] is False


def test_text_checker_reports_banned_copy():
    directory = "D:/temp/pe-inspector/tests"
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "copy_%s.md" % uuid.uuid4().hex)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("This is a game-changer\u2014and a seamless experience.\n")
        result = subprocess.run(
            [sys.executable, "tools/check_text.py", path],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "game-changer" in result.stdout
        assert "em dash" in result.stdout
    finally:
        os.remove(path)


def test_scan_clean(hardened_pe):
    data = core.scan(hardened_pe)
    assert data["score"] == 0
    assert data["level"] == "low"
    assert data["reasons"] == []
    assert "not a malware verdict" in data["disclaimer"]


def test_scan_risky(risky_pe):
    data = core.scan(risky_pe)
    ids = {reason["id"] for reason in data["reasons"]}
    assert {"wx_section", "high_entropy", "suspicious_imports", "no_aslr", "no_dep", "overlay"} <= ids
    assert data["score"] >= 60
    assert data["level"] == "high"


def test_suspicious_flag_logic():
    assert "CreateRemoteThread" in core.SUSPICIOUS_IMPORTS
    assert "NotARealApi" not in core.SUSPICIOUS_IMPORTS


def test_cli_info(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["info", minimal_pe])
    assert res.exit_code == 0, res.output
    assert "number_of_sections: 1" in res.output


def test_cli_info_json(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["info", minimal_pe, "--json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["machine"] == "i386"


def test_cli_headers(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["headers", minimal_pe])
    assert res.exit_code == 0, res.output
    assert "checksum matches:      yes" in res.output
    assert "DYNAMIC_BASE" in res.output


def test_cli_sections_json(minimal_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["sections", minimal_pe, "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data[0]["name"] == ".text"


def test_cli_imports(imports_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["imports", imports_pe])
    assert res.exit_code == 0, res.output
    assert "kernel32.dll!CreateRemoteThread [SUSPICIOUS]" in res.output


def test_cli_imports_suspicious(imports_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["imports", imports_pe, "--suspicious"])
    assert res.exit_code == 0, res.output
    assert "MessageBoxA" not in res.output


def test_cli_exports(exports_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["exports", exports_pe])
    assert res.exit_code == 0, res.output
    assert "Alpha" in res.output
    json_res = runner.invoke(cli.cli, ["exports", exports_pe, "--json"])
    assert len(json.loads(json_res.output)["exports"]) == 3


def test_cli_resources(resources_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["resources", resources_pe])
    assert res.exit_code == 0, res.output
    assert "RT_ICON" in res.output
    assert "TOTAL" in res.output


def test_cli_version(version_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["version", version_pe])
    assert res.exit_code == 0, res.output
    assert "CompanyName: Acme Tools" in res.output
    assert "file_version: 1.2.3.4" in res.output


def test_cli_overlay(overlay_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["overlay", overlay_pe])
    assert res.exit_code == 0, res.output
    assert "overlay_size: 448 bytes" in res.output


def test_cli_signature(signature_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["signature", signature_pe])
    assert res.exit_code == 0, res.output
    assert "present: yes" in res.output
    assert "validation: not performed" in res.output


def test_cli_scan(risky_pe):
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["scan", risky_pe])
    assert res.exit_code == 0, res.output
    assert "(high)" in res.output
    json_res = runner.invoke(cli.cli, ["scan", risky_pe, "--json"])
    data = json.loads(json_res.output)
    assert data["level"] == "high"


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
    res = runner.invoke(cli.cli, ["report", minimal_pe, "--format", "json"])
    json.loads(res.output)


def test_report_text_explains_findings_and_signature_limits(risky_pe):
    report = core.generate_report(risky_pe)
    assert "What this means" in report
    assert "not antivirus" in report.lower()
    assert "not proof that a file is malicious" in report.lower()
    assert "writable and executable" in report
    assert "Signature: Not found" in report
    assert "signature presence does not mean the signature is valid" in report.lower()


def test_report_signature_present_is_not_validation(signature_pe):
    report = core.generate_report(signature_pe)
    assert "Signature: Present" in report
    assert "validity was not checked" in report.lower()


def test_report_json_preserves_fields_and_adds_context(minimal_pe):
    payload = json.loads(core.generate_report(minimal_pe, fmt="json"))
    assert {"info", "sections", "imports", "entropy", "suspicious_imports"} <= set(payload)
    assert payload["signature"]["present"] is False
    assert payload["signature"]["validation_performed"] is False
    assert payload["scan"]["score"] == 0


def test_cli_report_accepts_path_with_spaces(minimal_pe):
    path_with_spaces = "D:/temp/pe-inspector/tests/curious user's copy.exe"
    with open(minimal_pe, "rb") as source, open(path_with_spaces, "wb") as target:
        target.write(source.read())
    try:
        result = CliRunner().invoke(cli.cli, ["report", path_with_spaces])
        assert result.exit_code == 0, result.output
        assert "What this means" in result.output
        assert "Signature: Not found" in result.output
        assert "Type: 32-bit x86 Windows file" in result.output
    finally:
        gc.collect()
        os.remove(path_with_spaces)


def test_cli_help():
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["--help"])
    assert res.exit_code == 0
    for command in ("info", "headers", "sections", "imports", "exports", "resources", "version", "overlay", "signature", "scan", "entropy", "report"):
        assert command in res.output


def test_cli_rejects_non_pe():
    directory = "D:/temp/pe-inspector/tests"
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "junk_%s.exe" % uuid.uuid4().hex)
    with open(path, "wb") as fh:
        fh.write(b"not a pe file")
    try:
        runner = CliRunner()
        res = runner.invoke(cli.cli, ["info", path])
        assert res.exit_code == 1
        assert "not a valid PE file" in res.output
    finally:
        os.remove(path)


def test_missing_file():
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["info", "D:/temp/pe-inspector/nonexistent.exe"])
    assert res.exit_code != 0
