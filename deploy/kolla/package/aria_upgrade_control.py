#!/usr/bin/env python3
"""Classify an Aria runtime upgrade without changing host state."""

import argparse
import json
import re
from collections import namedtuple
from pathlib import Path


DATAPATH_KEYS = (
    "snapshot_schema_version",
    "ebpf_abi_version",
    "map_schema_version",
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
IMAGE_IDENTITY_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*"
    r"(?::[a-z0-9][a-z0-9._-]*)?@sha256:[0-9a-f]{64}$"
)
REQUIRED_IMAGES = ("neutron-aria-agent", "aria-datapath")
UpgradeClassification = namedtuple("UpgradeClassification", ("path", "reasons"))


def load_manifest(path):
    """Load one release manifest as a JSON object."""
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        raise ValueError(f"manifest cannot be loaded: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    return manifest


def _valid_compatibility(manifest):
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


def is_valid_image_identity(identity):
    """Return true only for a conservative named immutable image reference."""
    return isinstance(identity, str) and IMAGE_IDENTITY_RE.fullmatch(identity) is not None


def _image_identities(manifest):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("images"), list):
        return None
    identities = {}
    for image in manifest["images"]:
        if not isinstance(image, dict):
            return None
        name = image.get("name")
        identity = image.get("identity")
        if not isinstance(name, str) or not isinstance(identity, str):
            return None
        if name in identities or not is_valid_image_identity(identity):
            return None
        identities[name] = identity
    if not all(name in identities for name in REQUIRED_IMAGES):
        return None
    return identities


def _unknown():
    return UpgradeClassification("planned_maintenance", ("unknown_compatibility",))


def classify_upgrade(current, candidate, force_maintenance=False):
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

    agent_changed = (
        current_images["neutron-aria-agent"]
        != candidate_images["neutron-aria-agent"]
    )
    datapath_changed = (
        current_images["aria-datapath"] != candidate_images["aria-datapath"]
    )
    if agent_changed and datapath_changed:
        return UpgradeClassification(
            "planned_maintenance", ("joint_agent_datapath_change",)
        )
    if (
        current_compatibility["uds_schema_min"]
        > candidate_compatibility["uds_schema_max"]
        or candidate_compatibility["uds_schema_min"]
        > current_compatibility["uds_schema_max"]
    ):
        return UpgradeClassification(
            "planned_maintenance", ("uds_schema_incompatible",)
        )
    if (
        current_compatibility["maintenance_gate_capable"]
        != candidate_compatibility["maintenance_gate_capable"]
    ):
        return UpgradeClassification(
            "planned_maintenance", ("maintenance_gate_capability_changed",)
        )
    changed_keys = tuple(
        sorted(
            key
            for key in DATAPATH_KEYS
            if current_compatibility[key] != candidate_compatibility[key]
        )
    )
    if changed_keys:
        return UpgradeClassification("planned_maintenance", changed_keys)
    if agent_changed and not datapath_changed:
        return UpgradeClassification("hot_agent", ("agent_only",))
    if datapath_changed:
        return UpgradeClassification("hot_datapath", ("compatible_datapath",))
    return UpgradeClassification("hot_agent", ("no_runtime_change",))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command")
    classify = command.add_parser("classify", help="print a read-only upgrade path")
    classify.add_argument("--current", type=Path, required=True)
    classify.add_argument("--candidate", type=Path, required=True)
    classify.add_argument("--force-maintenance", action="store_true")
    return parser.parse_args(argv)


def _print_result(result):
    print(json.dumps(
        {"path": result.path, "reasons": list(result.reasons)},
        sort_keys=True,
        separators=(",", ":"),
    ))


def main(argv=None):
    args = parse_args(argv)
    if args.command != "classify":
        _print_result(_unknown())
        return 0
    try:
        current = load_manifest(args.current)
        candidate = load_manifest(args.candidate)
        result = classify_upgrade(current, candidate, args.force_maintenance)
    except (OSError, ValueError, RecursionError):
        result = _unknown()
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
