# pe-inspector

`pe-inspector` reads Windows EXE and DLL files and gives you a report about what they contain. It does not run the file, change it, or upload it anywhere.

This is a small inspection aid, not antivirus. A clean report does not prove a file is safe, and a reported clue does not prove it is malicious. Do not run a file you do not trust just because this tool reports no clues.

## Quick start on Windows

Install Python 3.9 or newer, then open PowerShell in this project folder and run:

```powershell
py -m pip install -e .
```

To inspect a file, use one command. Put the file path in quotes, especially if it contains spaces. You can type the path or drag the EXE from File Explorer into the terminal, then put quotes around the path:

```powershell
pe-inspector report "C:\Users\you\Downloads\setup file.exe"
```

The report is printed in the terminal. The file is read as data and is never launched by pe-inspector. Be careful not to double-click an EXE you are unsure about.

## Understanding the report

- **Heuristic indicator score** counts a limited set of patterns, such as code that can also be written to, unusually dense sections, selected Windows APIs, or data appended to the file. It is not a probability, safety rating, or antivirus result. Software such as installers, debuggers, and system tools can match these patterns.
- **Signature: Present** only means the file has a certificate entry in its headers. pe-inspector does not check whether the signature is genuine, trusted, current, or still matches the file. Signature presence is not validation.
- **No selected indicators matched** means only that these specific checks found nothing. It does not mean the file is safe.
- **SHA-256** is a fingerprint you can use to compare the file with a trusted source. By itself, it does not say whether the file is safe.

Example output (illustrative, not a scan of a real program):

```text
EXE check: example.exe
============================================================
What this means
This is a static check. The file was read, not run.
Heuristics are not antivirus and cannot tell you whether a file is safe.
A matching indicator is not proof that a file is malicious.

Heuristic indicator score: 0/100 (low)
This is a count of selected clues, not a probability or safety rating.
No selected indicators matched. That does not prove the file is safe.

Signature: Not found
Signature presence does not mean the signature is valid. Signature validity was not checked.

File details
  Name: example.exe
  Size: 2048 bytes
  Type: 32-bit x86 Windows file
  SHA-256: <64-character file fingerprint>
```

## Other commands

The `report` command is the recommended starting point. For individual details, use:

```powershell
pe-inspector info "FILE.exe"          # file type, size, and fingerprints
pe-inspector sections "FILE.exe"      # parts of the file and their access flags
pe-inspector imports "FILE.exe"       # Windows functions the program refers to
pe-inspector scan "FILE.exe"          # selected static clues and their score
pe-inspector signature "FILE.exe"    # certificate entry presence, not validation
pe-inspector report "FILE.exe" --format json
```

Other commands include `headers`, `exports`, `resources`, `version`, `overlay`, and `entropy`. Run `pe-inspector --help` or `pe-inspector COMMAND --help` for details. Commands support `--json` when they return structured data. `report` supports `--format text`, `--format markdown`, or `--format json`.

## Development

```bash
pip install -e ".[dev]"
pytest
python tools/check_text.py
```

Tests build small PE fixtures locally and do not need Windows binaries from another source.

## License

MIT
