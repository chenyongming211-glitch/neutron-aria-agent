#!/usr/bin/env python3
"""Classify an Aria runtime upgrade without changing host state."""

from __future__ import annotations

import argparse
import json
import re
from collections import namedtuple
from pathlib import Path


DATAPATH_KEYS = (
    "snapshot_schema_version",
    "ebpf_abi_hash",
    "map_schema_hash",
    "wal_schema_version",
    "runtime_state_schema_version",
    "minimum_kernel_profile",
    "managed_domain_contract_version",
)
REQUIRED_COMPATIBILITY = {
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
    "ebpf_abi_hash": str,
    "map_schema_hash": str,
}
IMAGE_IDENTITY_RE = re.compile(r"^[A-Za-z0-9_./:-]+@sha256:[0-9a-f]{64}$")
REQUIRED_IMAGES = ("neutron-aria-agent", "aria-datapath")
UpgradeClassification = namedtuple("UpgradeClassification", ("path", "reasons"))


def load_manifest(path: Path) -> dict:
    """Load one release manifest as a JSON object."""
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"manifest cannot be loaded: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    return manifest


def _valid_compatibility(manifest: object) -> dict | None:
    if not isinstance(manifest, dict):
        return None
    compatibility = manifest.get("runtime_compatibility")
    if not isinstance(compatibility, dict):
        return None
    if set(compatibility) != set(REQUIRED_COMPATIBILITY):
        return None
    for key, expected_type in REQUIRED_COMPATIBILITY.items():
        value = compatibility[key]
        if expected_type is int:
            if type(value) is not int or value < 0:
                return None
        elif type(value) is not expected_type:
            return None
        elif expected_type is str and not value:
            return None
    if not all(
        re.fullmatch(r"[0-9a-f]{64}", compatibility[key])
        for key in ("ebpf_abi_hash", "map_schema_hash")
    ):
        return None
    if compatibility["schema_version"] != 1:
        return None
    if compatibility["uds_schema_min"] > compatibility["uds_schema_max"]:
        return None
    return compatibility


def _image_identities(manifest: object) -> dict[str, str] | None:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("images"), list):
        return None
    identities: dict[str, str] = {}
    for image in manifest["images"]:
        if not isinstance(image, dict):
            return None
        name = image.get("name")
        identity = image.get("identity")
        if not isinstance(name, str) or not isinstance(identity, str):
            return None
        if name in identities or not IMAGE_IDENTITY_RE.fullmatch(identity):
            return None
        identities[name] = identity
    if not all(name in identities for name in REQUIRED_IMAGES):
        return None
    return identities


def _unknown() -> UpgradeClassification:
    return UpgradeClassification("planned_maintenance", ("unknown_compatibility",))


def classify_upgrade(
    current: dict, candidate: dict, force_maintenance: bool = False
) -> UpgradeClassification:
    """Choose a deterministic path from two immutable release manifests."""
    if force_maintenance:
        return UpgradeClassification("planned_maintenance", ("operator_forced",))

    current_compatibility = _valid_compatibility(current)
    candidate_compatibility = _valid_compatibility(candidate)
    current_images = _image_identities(current)
    candidate_images = _image_identities(candidate)
    if not all(
        (current_compatibility, candidate_compatibility, current_images, candidate_images)
    ):
        return _unknown()

    changed_keys = tuple(
        sorted(
            key
            for key in DATAPATH_KEYS
            if current_compatibility[key] != candidate_compatibility[key]
        )
    )
    if changed_keys:
        return UpgradeClassification("planned_maintenance", changed_keys)

    agent_changed = (
        current_images["neutron-aria-agent"]
        != candidate_images["neutron-aria-agent"]
    )
    datapath_changed = (
        current_images["aria-datapath"] != candidate_images["aria-datapath"]
    )
    if agent_changed and not datapath_changed:
        return UpgradeClassification("hot_agent", ("agent_only",))
    if datapath_changed:
        return UpgradeClassification("hot_datapath", ("compatible_datapath",))
    return UpgradeClassification("hot_agent", ("no_runtime_change",))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    classify = command.add_parser("classify", help="print a read-only upgrade path")
    classify.add_argument("--current", type=Path, required=True)
    classify.add_argument("--candidate", type=Path, required=True)
    classify.add_argument("--force-maintenance", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        current = load_manifest(args.current)
        candidate = load_manifest(args.candidate)
        result = classify_upgrade(current, candidate, args.force_maintenance)
    except ValueError:
        result = _unknown()
    print(json.dumps({"path": result.path, "reasons": list(result.reasons)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
