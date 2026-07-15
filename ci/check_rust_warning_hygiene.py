#!/usr/bin/env python3
"""Guard the structural fixes that keep Rust/eBPF builds warning-free."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise AssertionError(f"missing required file: {relative}")
    return path.read_text(encoding="utf-8")


def require(text: str, needle: str, source: str) -> None:
    if needle not in text:
        raise AssertionError(f"{source} must contain {needle!r}")


def forbid(text: str, needle: str, source: str) -> None:
    if needle in text:
        raise AssertionError(f"{source} must not contain {needle!r}")


def verify_pod_layouts(source: str) -> None:
    """Reject implicit padding in every type passed to unsafe aya::Pod."""
    primitive_layouts = {
        "u8": (1, 1),
        "u16": (2, 2),
        "u32": (4, 4),
        "i32": (4, 4),
        "u64": (8, 8),
    }

    pod_block = re.search(r"impl_aya_pod!\((.*?)\n    \);", source, re.DOTALL)
    if pod_block is None:
        raise AssertionError("abi/src/lib.rs must contain the aya::Pod implementation list")
    pod_types = re.findall(r"\b([A-Z]\w+)\s*,", pod_block.group(1))

    for pod_type in pod_types:
        struct = re.search(
            rf"pub struct {re.escape(pod_type)}\s*\{{(.*?)\n\}}",
            source,
            re.DOTALL,
        )
        if struct is None:
            raise AssertionError(f"aya::Pod type {pod_type} has no struct definition")

        offset = 0
        struct_alignment = 1
        for field_name, field_type in re.findall(
            r"pub\s+(\w+):\s*([^,\n]+)", struct.group(1)
        ):
            field_type = field_type.strip()
            if field_type in primitive_layouts:
                size, alignment = primitive_layouts[field_type]
            else:
                array = re.fullmatch(
                    r"\[(u8|u16|u32|u64|i32);\s*(\d+)\]", field_type
                )
                if array is None:
                    raise AssertionError(
                        f"unsupported aya::Pod field type {pod_type}.{field_name}: {field_type}"
                    )
                element_size, alignment = primitive_layouts[array.group(1)]
                size = element_size * int(array.group(2))

            aligned_offset = (offset + alignment - 1) // alignment * alignment
            if aligned_offset != offset:
                raise AssertionError(
                    f"implicit padding before aya::Pod field {pod_type}.{field_name}"
                )
            offset += size
            struct_alignment = max(struct_alignment, alignment)

        aligned_size = (
            (offset + struct_alignment - 1) // struct_alignment * struct_alignment
        )
        if aligned_size != offset:
            raise AssertionError(f"implicit tail padding in aya::Pod type {pod_type}")


def main() -> None:
    workspace = read("Cargo.toml")
    abi_manifest = read("abi/Cargo.toml")
    abi_source = read("abi/src/lib.rs")
    core_manifest = read("core/Cargo.toml")
    core_common = read("core/src/common.rs")
    ebpf_manifest = read("ebpf/Cargo.toml")
    ebpf_common = read("ebpf/src/common.rs")
    ebpf_root = read("ebpf/src/lib.rs")
    ebpf_tcprt = read("ebpf/src/tcprt.rs")
    core_runtime = read("core/src/ebpf_ops/runtime.rs")
    core_replay = read("core/src/ebpf_ops/replay.rs")
    instance = read("agent/src/instance.rs")
    neutron_api = read("agent/src/neutron_api.rs")
    api_client = read("user/src/api_client.rs")
    workflow = read(".github/workflows/build.yml")
    builder = read("Dockerfile.builder")

    require(workspace, '"abi"', "Cargo.toml")
    require(abi_manifest, 'name = "aria-ebpf-abi"', "abi/Cargo.toml")
    require(abi_source, "#![no_std]", "abi/src/lib.rs")
    forbid(abi_source, "#[allow(", "abi/src/lib.rs")
    verify_pod_layouts(abi_source)
    for field in (
        "_pad_last_payload_len: [u8; 2]",
        "_pad_prev_payload_len: [u8; 2]",
        "_pad_last_resp_payload_len: [u8; 2]",
        "_pad3: [u8; 4]",
        "_pad: [u8; 1]",
    ):
        require(abi_source, field, "abi/src/lib.rs")
    require(
        abi_source,
        "reserved_xdp_trace_hook_discriminators_remain_stable",
        "abi/src/lib.rs",
    )

    require(core_manifest, "aria-ebpf-abi", "core/Cargo.toml")
    require(ebpf_manifest, "aria-ebpf-abi", "ebpf/Cargo.toml")
    require(
        core_common,
        "pub use aria_ebpf_abi::userspace::*;",
        "core/src/common.rs",
    )
    require(ebpf_common, "pub use aria_ebpf_abi::*;", "ebpf/src/common.rs")
    forbid(core_common, '#[path = "../../ebpf/src/common.rs"]', "core/src/common.rs")
    forbid(ebpf_root, "#![allow(dead_code)]", "ebpf/src/lib.rs")
    for assignment in (
        "(*val)._pad_last_payload_len = [0; 2];",
        "(*val)._pad_prev_payload_len = [0; 2];",
        "(*val)._pad_last_resp_payload_len = [0; 2];",
        "(*val)._pad3 = [0; 4];",
    ):
        require(ebpf_tcprt, assignment, "ebpf/src/tcprt.rs")
    if core_runtime.count("_pad: [0; 1]") != 3:
        raise AssertionError(
            "core/src/ebpf_ops/runtime.rs must initialize all FirewallConfig padding"
        )
    require(core_replay, "_pad: [0; 1]", "core/src/ebpf_ops/replay.rs")

    forbid(instance, "fn tc_acl_links_complete(", "agent/src/instance.rs")
    forbid(
        neutron_api,
        "fn translate_neutron_acl(port_id: &str, acl: &NeutronAclSnapshot)",
        "agent/src/neutron_api.rs",
    )
    forbid(api_client, "pub async fn list_drops(", "user/src/api_client.rs")
    forbid(api_client, "pub async fn flush_drops(", "user/src/api_client.rs")

    require(workflow, "nightly-2026-07-14", ".github/workflows/build.yml")
    require(
        workflow,
        "bpf-linker-x86_64-unknown-linux-musl.tar.zst",
        ".github/workflows/build.yml",
    )
    require(
        workflow,
        "4dda77daab6c5f120a468e6d3ede2498f5bd47ece712172cfb7290176d93d015",
        ".github/workflows/build.yml",
    )
    forbid(workflow, "LD_LIBRARY_PATH", ".github/workflows/build.yml")
    forbid(
        workflow,
        "cargo +nightly install bpf-linker",
        ".github/workflows/build.yml",
    )
    if workflow.count("RUSTFLAGS: -D warnings") != 4:
        raise AssertionError(
            ".github/workflows/build.yml must reject warnings in all four Rust test/build steps"
        )

    require(builder, "nightly-2026-07-14", "Dockerfile.builder")
    require(
        builder,
        "bpf-linker-${bpf_linker_arch}-unknown-linux-musl.tar.zst",
        "Dockerfile.builder",
    )
    require(
        builder,
        "4dda77daab6c5f120a468e6d3ede2498f5bd47ece712172cfb7290176d93d015",
        "Dockerfile.builder",
    )
    require(
        builder,
        "c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de",
        "Dockerfile.builder",
    )
    require(builder, "ARG TARGETARCH", "Dockerfile.builder")
    forbid(builder, "cargo install bpf-linker", "Dockerfile.builder")

    print("Rust warning hygiene contracts passed")


if __name__ == "__main__":
    main()
