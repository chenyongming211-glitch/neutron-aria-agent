#!/usr/bin/env python3
"""Check the merge-gate contracts encoded by the Build workflow."""

import re
from fnmatch import fnmatchcase
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
MAINTAINED_BRANCH = "v0.9-neutron-agent"


def _mapping_block(source: str, key: str, indent: int) -> list[str]:
    """Return the indented YAML lines nested directly below ``key``."""
    lines = source.splitlines()
    marker = f"{' ' * indent}{key}:"
    for index, line in enumerate(lines):
        if line == marker:
            block: list[str] = []
            for nested in lines[index + 1 :]:
                if nested.strip() and len(nested) - len(nested.lstrip()) <= indent:
                    break
                block.append(nested)
            return block
    raise AssertionError(f"Build workflow must define {key!r} at indent {indent}")


def _sequence(block: list[str], key: str, indent: int) -> list[str]:
    """Read an inline or block YAML string sequence from a small mapping."""
    marker = f"{' ' * indent}{key}:"
    for index, line in enumerate(block):
        if not line.startswith(marker):
            continue
        value = line[len(marker) :].strip()
        if value.startswith("[") and value.endswith("]"):
            return [
                item.strip().strip("'\"")
                for item in value[1:-1].split(",")
                if item.strip()
            ]
        if value:
            raise AssertionError(f"Build workflow {key!r} must be a YAML sequence")

        items: list[str] = []
        for nested in block[index + 1 :]:
            if nested.strip() and len(nested) - len(nested.lstrip()) <= indent:
                break
            stripped = nested.strip()
            if stripped.startswith("- "):
                items.append(stripped[2:].strip().strip("'\""))
        return items
    raise AssertionError(f"Build workflow must define {key!r}")


def _patterns_include_branch(patterns: list[str], branch: str) -> bool:
    included = False
    for pattern in patterns:
        if pattern.startswith("!"):
            if fnmatchcase(branch, pattern[1:]):
                included = False
        elif fnmatchcase(branch, pattern):
            included = True
    return included


def verify_workflow_contract(source: str) -> None:
    pull_request = _mapping_block(source, "pull_request", 2)
    branches = _sequence(pull_request, "branches", 4)
    if not _patterns_include_branch(branches, MAINTAINED_BRANCH):
        raise AssertionError(
            "Build workflow pull requests must include maintained branch "
            f"{MAINTAINED_BRANCH!r}; found {branches!r}"
        )

    required_commands = (
        "python3 -m unittest ci.test_rust_build_required",
        "python3 -m unittest ci.test_rust_warning_hygiene",
        "python3 ci/rust_build_required.py",
    )
    for command in required_commands:
        if command not in source:
            raise AssertionError(f"Build workflow must execute {command!r}")

    if "grep -Eq '^(Cargo" in source:
        raise AssertionError(
            "Build workflow must delegate path classification to rust_build_required.py"
        )
    if re.search(r"git diff --name-only(?! --no-renames)", source):
        raise AssertionError(
            "Build workflow must disable rename detection so both changed paths are classified"
        )
    if re.search(r"git diff --name-only --no-renames[^\n]*\|\| true", source):
        raise AssertionError(
            "Build workflow must not hide changed-path collection failures"
        )
    if "git diff --name-only --no-renames HEAD~1 HEAD" in source:
        raise AssertionError(
            "Build workflow must fail closed instead of inspecting only the final push commit"
        )


def main() -> None:
    verify_workflow_contract(WORKFLOW.read_text(encoding="utf-8"))
    print("Build workflow contracts passed")


if __name__ == "__main__":
    main()
