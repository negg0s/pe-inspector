# pe-inspector

A small command-line tool for inspecting Windows PE (Portable Executable) files.

## Install

```bash
pip install -e .
```

## Usage

```bash
pe-inspector info FILE
pe-inspector sections FILE [--json]
pe-inspector imports FILE [--suspicious]
pe-inspector entropy FILE
pe-inspector report FILE [--format text|json|markdown]
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT