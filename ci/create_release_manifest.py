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
IMAGE_COMPONENT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
RUNTIME_COMPATIBILITY_FIELDS = {
    "schema_version": int,
    "uds_schema_min": int,
    "uds_schema_max": int,
    "snapshot_schema_version": int,
    "ebpf_abi_version": int,
    "map_schema_version": int,
    "wal_schema_version": int,
    "runtime_state_schema_version": int,
    "minimum_kernel_profile": str,
    "managed_domain_contract_version": str,
    "maintenance_gate_capable": bool,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_length_delimited_files(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, byteorder="big"))
        digest.update(content)
    return digest.hexdigest()


def load_runtime_compatibility(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_members
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"runtime compatibility JSON is invalid: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("runtime compatibility must be a JSON object")

    expected = set(RUNTIME_COMPATIBILITY_FIELDS)
    actual = set(payload)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise ValueError("runtime compatibility is missing fields: " + ", ".join(missing))
    if unknown:
        raise ValueError("runtime compatibility has unknown fields: " + ", ".join(unknown))

    for key, expected_type in RUNTIME_COMPATIBILITY_FIELDS.items():
        value = payload[key]
        if expected_type is int:
            if type(value) is not int or value < 0:
                raise ValueError(f"runtime compatibility {key} must be a non-negative integer")
        elif type(value) is not expected_type:
            raise ValueError(f"runtime compatibility {key} has an invalid type")
        elif expected_type is str and not value:
            raise ValueError(f"runtime compatibility {key} must not be empty")
    return payload


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object only when each member name occurs once."""
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON object member: {key}")
        payload[key] = value
    return payload


def is_valid_image_identity(identity: object) -> bool:
    """Return true only for a conservative named immutable image reference."""
    if not isinstance(identity, str) or "@sha256:" not in identity:
        return False
    name, digest = identity.rsplit("@sha256:", 1)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False
    parts = name.split("/")
    if not parts or any(not part for part in parts):
        return False
    for index, part in enumerate(parts):
        if ":" not in part:
            if not IMAGE_COMPONENT_RE.fullmatch(part):
                return False
            continue
        value, separator = part.rsplit(":", 1)
        if not value or not separator:
            return False
        if index == 0 and len(parts) > 1:
            if not IMAGE_COMPONENT_RE.fullmatch(value):
                return False
            if not separator.isdigit() or not 1 <= int(separator) <= 65535:
                return False
        elif index == len(parts) - 1:
            if not IMAGE_COMPONENT_RE.fullmatch(value):
                return False
            if not IMAGE_COMPONENT_RE.fullmatch(separator):
                return False
        else:
            return False
    return True


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
    compatibility_path = repo_root / "release/runtime-compatibility.json"
    uds_contract_path = repo_root / "docs/neutron-uds-contract.json"
    abi_path = repo_root / "abi/src/lib.rs"
    map_schema_path = repo_root / "ebpf/src/maps.rs"
    for path in (
        version_path,
        support_path,
        compatibility_path,
        uds_contract_path,
        abi_path,
        map_schema_path,
    ):
        if not path.is_file():
            raise ValueError(f"required release input is missing: {path}")
    runtime_compatibility = load_runtime_compatibility(compatibility_path)
    runtime_compatibility["ebpf_abi_hash"] = sha256_file(abi_path)
    runtime_compatibility["map_schema_hash"] = sha256_length_delimited_files(
        (abi_path, map_schema_path)
    )

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
        if not is_valid_image_identity(identity):
            raise ValueError(
                f"image identity must end with @sha256:<64 lowercase hex>: {name}"
            )
        image_records.append({"name": name, "identity": identity})

    manifest: dict[str, object] = {
        "artifacts": artifact_records,
        "component_versions": component_versions(repo_root),
        "contracts": {
            "neutron_uds_sha256": sha256_file(uds_contract_path),
            "runtime_compatibility_sha256": sha256_file(compatibility_path),
            "support_matrix_sha256": sha256_file(support_path),
        },
        "images": image_records,
        "product": "aria-firewall-neutron",
        "product_version": version_path.read_text(encoding="utf-8").strip(),
        "release_version": "v" + version_path.read_text(encoding="utf-8").strip(),
        "runtime_compatibility": runtime_compatibility,
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
