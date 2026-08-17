#!/usr/bin/env python3
"""Create a deterministic release manifest and checksum list."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
IMAGE_IDENTITY_RE = re.compile(
    r"^[A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}$"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_named(values: list[str], label: str) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    names: set[str] = set()
    for value in values:
        if "=" not in value:
            raise ValueError(f"{label} must use name=value: {value!r}")
        name, item = value.split("=", 1)
        valid_name = NAME_RE.fullmatch(name)
        if label == "artifact":
            valid_name = (
                ARTIFACT_NAME_RE.fullmatch(name)
                and all(part not in (".", "..") for part in name.split("/"))
            )
        if not valid_name or not item:
            raise ValueError(f"invalid {label}: {value!r}")
        if name in names:
            raise ValueError(f"duplicate {label} name: {name}")
        names.add(name)
        parsed.append((name, item))
    return sorted(parsed)


def component_versions(repo_root: Path) -> dict[str, str]:
    cargo = (repo_root / "Cargo.toml").read_text(encoding="utf-8")
    cargo_match = re.search(
        r"(?ms)^\[workspace\.package\].*?^version\s*=\s*\"([^\"]+)\"",
        cargo,
    )
    python_init = (
        repo_root / "openstack/neutron_aria/neutron_aria/__init__.py"
    ).read_text(encoding="utf-8")
    python_match = re.search(r'^__version__\s*=\s*"([^"]+)"', python_init, re.M)
    client_setup = (
        repo_root / "openstack/neutronclient_aria/setup.py"
    ).read_text(encoding="utf-8")
    client_match = re.search(r'^\s*version\s*=\s*"([^"]+)"', client_setup, re.M)
    if not cargo_match or not python_match or not client_match:
        raise ValueError("component package versions could not be resolved")
    return {
        "python_neutron_adapter": python_match.group(1),
        "python_neutron_client": client_match.group(1),
        "rust_workspace": cargo_match.group(1),
    }


def build_manifest(
    repo_root: Path,
    source_commit: str,
    artifacts: list[tuple[str, str]],
    images: list[tuple[str, str]],
) -> tuple[dict[str, object], list[str]]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise ValueError("source commit must be a 40-character lowercase hex SHA")

    version_path = repo_root / "VERSION"
    support_path = repo_root / "release/support-matrix.json"
    uds_contract_path = repo_root / "docs/neutron-uds-contract.json"
    for path in (version_path, support_path, uds_contract_path):
        if not path.is_file():
            raise ValueError(f"required release input is missing: {path}")

    artifact_records: list[dict[str, object]] = []
    checksum_lines: list[str] = []
    for name, raw_path in artifacts:
        path = Path(raw_path).resolve()
        if not path.is_file():
            raise ValueError(f"artifact is missing: {path}")
        digest = sha256_file(path)
        artifact_records.append(
            {"name": name, "sha256": digest, "size_bytes": path.stat().st_size}
        )
        checksum_lines.append(f"{digest}  {name}")

    image_records: list[dict[str, str]] = []
    for name, identity in images:
        if not IMAGE_IDENTITY_RE.fullmatch(identity):
            raise ValueError(
                f"image identity must end with @sha256:<64 lowercase hex>: {name}"
            )
        image_records.append({"name": name, "identity": identity})

    manifest: dict[str, object] = {
        "artifacts": artifact_records,
        "component_versions": component_versions(repo_root),
        "contracts": {
            "neutron_uds_sha256": sha256_file(uds_contract_path),
            "support_matrix_sha256": sha256_file(support_path),
        },
        "images": image_records,
        "product": "aria-firewall-neutron",
        "product_version": version_path.read_text(encoding="utf-8").strip(),
        "schema_version": 1,
        "source_commit": source_commit,
    }
    return manifest, checksum_lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checksums-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        artifacts = parse_named(args.artifact, "artifact")
        images = parse_named(args.image, "image")
        manifest, checksum_lines = build_manifest(
            args.repo_root.resolve(), args.source_commit, artifacts, images
        )
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.checksums_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums = "".join(line + "\n" for line in checksum_lines)
    args.checksums_output.write_text(checksums, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
