"""Check documentation for punctuation and stock marketing language."""

import argparse
import sys
from pathlib import Path


BANNED_PHRASES = (
    "game-changer",
    "seamless",
    "seamlessly",
    "unlock the power",
    "in today's",
    "it's important to note",
    "in conclusion",
    "delve into",
    "cutting-edge",
)


def check_text(path):
    text = path.read_text(encoding="utf-8")
    problems = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "\u2014" in line:
            problems.append((line_number, "em dash"))
        if "\u2013" in line:
            problems.append((line_number, "en dash"))
        folded = line.casefold()
        for phrase in BANNED_PHRASES:
            if phrase in folded:
                problems.append((line_number, "banned phrase: %s" % phrase))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path("README.md")])
    args = parser.parse_args(argv)
    failed = False
    for path in args.paths:
        try:
            problems = check_text(path)
        except (OSError, UnicodeError) as exc:
            print("%s: %s" % (path, exc), file=sys.stderr)
            failed = True
            continue
        for line_number, problem in problems:
            print("%s:%d: %s" % (path, line_number, problem))
            failed = True
    if failed:
        return 1
    print("Text check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
