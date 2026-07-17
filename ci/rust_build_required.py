#!/usr/bin/env python3
"""Decide whether a set of changed paths requires the Rust/eBPF build."""

from __future__ import annotations

import sys
from collections.abc import Iterable


RUST_REQUIRED_FILES = frozenset(
    {
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "Dockerfile.builder",
        "aria-agent.service",
        "aria-firewall.service",
        "aria-firewall.spec",
        "docs/neutron-status-contract-v1-scenarios.json",
        "install.sh",
    }
)
RUST_REQUIRED_PREFIXES = (
    ".cargo/",
    ".github/workflows/",
    "abi/",
    "agent/",
    "api/",
    "ci/",
    "config/",
    "core/",
    "ebpf/",
    "tools/",
    "user/",
)
KNOWN_NON_RUST_PREFIXES = ("docs/",)
KNOWN_NON_RUST_FILES = frozenset({"README.md", "LICENSE"})
OPENSTACK_NON_RUST_SUFFIXES = (".py", ".pyi", ".txt", ".md", ".rst")
OPENSTACK_NON_RUST_FILES = frozenset(
    {"MANIFEST.in", "pyproject.toml", "setup.cfg", "tox.ini"}
)


def _normalized_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    path = value
    if not path or path != path.strip():
        return None
    if path.startswith(("/", "./")) or "\\" in path:
        return None
    if path == ".." or path.startswith("../") or "/../" in path:
        return None
    return path


def _known_non_rust_path(path: str) -> bool:
    if path in KNOWN_NON_RUST_FILES or path.startswith(KNOWN_NON_RUST_PREFIXES):
        return True
    if not path.startswith("openstack/"):
        return False
    name = path.rsplit("/", 1)[-1]
    return name in OPENSTACK_NON_RUST_FILES or name.endswith(
        OPENSTACK_NON_RUST_SUFFIXES
    )


def rust_build_required(paths: Iterable[str] | None) -> bool:
    """Fail closed unless every changed path is known to be non-Rust-only."""
    if paths is None:
        return True

    saw_path = False
    for value in paths:
        path = _normalized_path(value)
        if path is None:
            return True
        saw_path = True

        if path in RUST_REQUIRED_FILES or path.startswith(RUST_REQUIRED_PREFIXES):
            return True
        if _known_non_rust_path(path):
            continue
        return True

    return not saw_path


def main(argv: list[str]) -> int:
    paths = argv[1:] if len(argv) > 1 else sys.stdin.read().splitlines()
    print("true" if rust_build_required(paths) else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
