# pe-inspector

A command-line tool for inspecting Windows PE (Portable Executable) files. It reads files without running them.

## Install

```bash
pip install -e .
```

## Usage

```bash
pe-inspector info FILE
pe-inspector headers FILE
pe-inspector sections FILE
pe-inspector imports FILE
pe-inspector imports FILE --suspicious
pe-inspector exports FILE
pe-inspector resources FILE
pe-inspector version FILE
pe-inspector overlay FILE
pe-inspector signature FILE
pe-inspector entropy FILE
pe-inspector scan FILE
pe-inspector report FILE [--format text|json|markdown]
```

Most commands accept `--json`. The `info` command reports file hashes and basic image details. `headers` shows COFF and optional header fields, including the stored and computed checksum. `sections` lists section sizes, entropy, and access flags. `imports` can filter to a small set of imports often useful during triage. `exports` lists exported names and forwarders.

`resources` summarizes resource types and sizes. `version` reads VERSIONINFO fields when present. `overlay` reports bytes after the final section. `signature` reports the Authenticode certificate table location and header when present. It does not validate the certificate or signature. `scan` assigns a score from static indicators such as writable executable sections, high entropy, selected imports, missing ASLR or DEP flags, and overlay data. Treat this score as a triage aid, not a malware verdict.

Example:

```bash
pe-inspector headers sample.exe --json
pe-inspector scan sample.exe
```

## Development

```bash
pip install -e ".[dev]"
pytest
python tools/check_text.py
```

Tests build small PE fixtures locally and do not need Windows binaries from another source.

## License

MIT
