# Friendly EXE Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a curious Windows user inspect an EXE with one quoted, drag-and-drop-friendly command and understand a plain-language report without mistaking heuristics or signature presence for security validation.

**Architecture:** Improve the existing `report` command and its text/Markdown report generation, retaining JSON's existing fields while adding signature and heuristic context. Document Windows Terminal usage, safe handling, a sample report, and clear non-goals in README.

**Tech Stack:** Python 3.9+, Click, pefile, pytest.

**Spec:** User request in session, 2026-10-31.

## Global Constraints

- Work only under `D:\Projects\pe-inspector` and use existing dependencies.
- Keep inspection static: never execute the inspected EXE.
- Heuristics are not antivirus, and signature presence is not signature validation.
- Use plain language and avoid em/en dashes.

## Review Focus

- Paths with spaces or drag-and-drop quoting: document explicit quoted command and test CLI.
- Unsigned/signed files: report signature presence and explicitly say validity is not checked.
- Normal files matching a heuristic: explain indicators are clues and not proof; preserve score as triage context.
- Non-PE/missing path: retain clear CLI errors.
- JSON consumers: keep existing report keys and test enriched payload.

---

### Task 1: Make the report understandable

**Files:**
- Modify: `src/pe_inspector/core.py`
- Test: `tests/test_pe.py`

**Interfaces:** Add `signature` and `scan` to generated text/Markdown/JSON reports; preserve existing JSON keys.

- [x] Add failing tests asserting plain-language summary, score rationale, and explicit signature validation caveat for unsigned and signature-present fixtures, plus preserved JSON keys.
- [x] Run targeted tests and confirm they fail.
- [x] Implement report generation using existing `scan()` and `get_signature()` without changing scoring behavior.
- [x] Run targeted tests and confirm they pass.

### Task 2: Document the safe Windows workflow

**Files:**
- Modify: `README.md`
- Test: `tests/test_pe.py`

- [x] Add a failing CLI test for report output with an input path containing spaces and expected non-technical headings.
- [x] Run the targeted test and confirm it fails.
- [x] Document install/run, quoted and drag-and-drop-friendly syntax, report interpretation, safe handling, limitations, and a clearly labeled illustrative sample output.
- [x] Run the CLI test, all tests, text checker, and CLI help/report verification.
- [ ] Commit and push the verified changes.
