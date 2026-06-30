#!/usr/bin/env python3
from __future__ import print_function

import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_PATHS = [
    os.path.join("deploy", "kolla", "smoke"),
    os.path.join("deploy", "kolla", "package"),
]
HEREDOC_RE = re.compile(r"<<-?\s*'?PY'?")


def _repo_path(relpath):
    return os.path.join(ROOT, relpath)


def _iter_scripts(paths):
    for relpath in paths:
        path = _repo_path(relpath)
        if os.path.isdir(path):
            for dirpath, _, filenames in os.walk(path):
                for filename in sorted(filenames):
                    if filename.endswith(".sh"):
                        yield os.path.join(dirpath, filename)
        elif os.path.isfile(path):
            yield path
        else:
            raise SystemExit("ERROR: missing smoke script path: %s" % relpath)


def _extract_py_blocks(path):
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    index = 0
    while index < len(lines):
        if not HEREDOC_RE.search(lines[index]):
            index += 1
            continue

        start_line = index + 1
        body = []
        index += 1
        while index < len(lines) and lines[index].strip() != "PY":
            body.append(lines[index])
            index += 1

        if index == len(lines):
            raise SyntaxError("missing PY terminator", (path, start_line, 1, ""))

        yield start_line, "\n".join(body) + "\n"
        index += 1


def main():
    paths = sys.argv[1:] or DEFAULT_PATHS
    checked_blocks = 0
    errors = []

    for path in _iter_scripts(paths):
        relpath = os.path.relpath(path, ROOT)
        for start_line, source in _extract_py_blocks(path):
            checked_blocks += 1
            try:
                compile(source, "%s:%d" % (relpath, start_line), "exec")
            except SyntaxError as exc:
                errors.append(
                    "%s:%d: %s at embedded line %s col %s" % (
                        relpath,
                        start_line,
                        exc.msg,
                        exc.lineno,
                        exc.offset,
                    )
                )

    if errors:
        print("Embedded Python syntax errors found:", file=sys.stderr)
        for error in errors:
            print("  %s" % error, file=sys.stderr)
        return 1

    print("embedded smoke Python accepted")
    print("checked_blocks=%d" % checked_blocks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
