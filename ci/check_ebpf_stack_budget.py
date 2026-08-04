#!/usr/bin/env python3
"""Enforce a combined BPF call-path stack budget on a linked ELF artifact."""

from __future__ import print_function

import argparse
import json
import os
import struct
import sys


BPF_CALL_OPCODE = 0x85
BPF_PSEUDO_CALL = 1
DEFAULT_ENTRIES = ("tc_ingress", "tc_egress")


class BudgetExceeded(ValueError):
    pass


def decode_uleb128(data, offset):
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("ULEB128 value exceeds 64 bits")
    raise ValueError("truncated ULEB128 value")


def longest_path(entry, frames, calls):
    visiting = set()
    memo = {}

    def visit(name):
        if name not in frames:
            raise ValueError("missing stack frame for %s" % name)
        if name in visiting:
            raise ValueError("recursive BPF call graph at %s" % name)
        if name in memo:
            return memo[name]

        visiting.add(name)
        best_child_total = 0
        best_child_path = []
        for target in sorted(calls.get(name, set())):
            child_total, child_path = visit(target)
            if child_total > best_child_total:
                best_child_total = child_total
                best_child_path = child_path
        visiting.remove(name)

        result = (frames[name] + best_child_total, [name] + best_child_path)
        memo[name] = result
        return result

    return visit(entry)


def validate_budget(entries, frames, calls, max_path_bytes):
    reports = {}
    for entry in entries:
        total, path = longest_path(entry, frames, calls)
        reports[entry] = {
            "total_bytes": total,
            "path": [
                {"function": function, "frame_bytes": frames[function]}
                for function in path
            ],
        }
        if total > max_path_bytes:
            raise BudgetExceeded(
                "%s call path uses %d bytes exceeds %d byte budget"
                % (entry, total, max_path_bytes)
            )
    return reports


def _function_symbols(elf):
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        raise ValueError("ELF artifact has no .symtab")

    functions = {}
    by_location = {}
    for symbol in symtab.iter_symbols():
        if symbol["st_info"]["type"] != "STT_FUNC" or not symbol.name:
            continue
        section_index = symbol["st_shndx"]
        if not isinstance(section_index, int):
            continue
        record = {
            "name": symbol.name,
            "section_index": section_index,
            "value": int(symbol["st_value"]),
            "size": int(symbol["st_size"]),
        }
        functions[symbol.name] = record
        by_location[(section_index, record["value"])] = symbol.name

    for entry in DEFAULT_ENTRIES:
        if entry not in functions:
            raise ValueError("ELF artifact is missing %s" % entry)
    return symtab, functions, by_location


def _relocations_by_target_section(elf):
    relocations = {}
    for section in elf.iter_sections():
        if section["sh_type"] not in ("SHT_REL", "SHT_RELA"):
            continue
        target_section_index = int(section["sh_info"])
        symtab = elf.get_section(section["sh_link"])
        target = relocations.setdefault(target_section_index, {})
        for relocation in section.iter_relocations():
            target[int(relocation["r_offset"])] = (
                relocation,
                symtab.get_symbol(relocation["r_info_sym"]),
            )
    return relocations


def _resolve_section_target(symbol, immediate, by_location):
    section_index = symbol["st_shndx"]
    if not isinstance(section_index, int):
        raise ValueError("pseudo-call relocation has invalid section target")

    # BPF section relocations store the target instruction index minus one in
    # the call immediate. The loader later rebases it against the entry section.
    target_value = (immediate + 1) * 8
    target = by_location.get((section_index, target_value))
    if target is None:
        raise ValueError(
            "unknown section-relative pseudo-call target section=%d value=%d"
            % (section_index, target_value)
        )
    return target


def read_call_graph(elf, functions, by_location, relocations):
    calls = {name: set() for name in functions}
    for name, function in functions.items():
        section = elf.get_section(function["section_index"])
        data = section.data()
        start = function["value"]
        end = start + function["size"]
        if end > len(data) or start % 8 != 0 or function["size"] % 8 != 0:
            raise ValueError("invalid BPF function range for %s" % name)

        for offset in range(start, end, 8):
            instruction = data[offset : offset + 8]
            opcode = instruction[0]
            source_register = instruction[1] >> 4
            if opcode != BPF_CALL_OPCODE or source_register != BPF_PSEUDO_CALL:
                continue

            immediate = struct.unpack_from("<i", instruction, 4)[0]
            relocation_entry = relocations.get(function["section_index"], {}).get(offset)
            if relocation_entry is not None:
                _, symbol = relocation_entry
                symbol_type = symbol["st_info"]["type"]
                if symbol_type == "STT_FUNC" and symbol.name:
                    target = symbol.name
                elif symbol_type == "STT_SECTION":
                    target = _resolve_section_target(symbol, immediate, by_location)
                else:
                    raise ValueError(
                        "unsupported pseudo-call relocation %s in %s"
                        % (symbol_type, name)
                    )
            else:
                target_value = offset + 8 + immediate * 8
                target = by_location.get((function["section_index"], target_value))
                if target is None:
                    raise ValueError(
                        "unknown pseudo-call target section=%d value=%d in %s"
                        % (function["section_index"], target_value, name)
                    )
            calls[name].add(target)
    return calls


def read_stack_frames(elf, symtab, functions, by_location):
    stack_section = elf.get_section_by_name(".stack_sizes")
    if stack_section is None:
        raise ValueError(
            "ELF artifact has no .stack_sizes; build eBPF with -Z emit-stack-sizes"
        )

    stack_section_index = None
    for index, section in enumerate(elf.iter_sections()):
        if section.name == ".stack_sizes":
            stack_section_index = index
            break
    if stack_section_index is None:
        raise ValueError("failed to locate .stack_sizes section index")

    relocation_section = None
    for section in elf.iter_sections():
        if section["sh_type"] in ("SHT_REL", "SHT_RELA") and int(
            section["sh_info"]
        ) == stack_section_index:
            relocation_section = section
            break
    if relocation_section is None:
        raise ValueError("ELF .stack_sizes section has no relocation section")

    address_size = elf.elfclass // 8
    byte_order = "little" if elf.little_endian else "big"
    data = stack_section.data()
    frames = {}
    for relocation in sorted(
        relocation_section.iter_relocations(), key=lambda item: int(item["r_offset"])
    ):
        entry_offset = int(relocation["r_offset"])
        symbol = symtab.get_symbol(relocation["r_info_sym"])
        symbol_type = symbol["st_info"]["type"]
        if symbol_type == "STT_FUNC" and symbol.name:
            function_name = symbol.name
        elif symbol_type == "STT_SECTION":
            section_index = symbol["st_shndx"]
            if relocation_section["sh_type"] == "SHT_RELA":
                address = int(relocation["r_addend"])
            else:
                address = int.from_bytes(
                    data[entry_offset : entry_offset + address_size], byte_order
                )
            function_name = by_location.get((section_index, address))
            if function_name is None:
                raise ValueError(
                    "unknown .stack_sizes section target section=%s value=%d"
                    % (section_index, address)
                )
        else:
            raise ValueError(
                "unsupported .stack_sizes relocation symbol type %s" % symbol_type
            )

        frame_size, _ = decode_uleb128(data, entry_offset + address_size)
        frames[function_name] = frame_size

    missing = sorted(set(functions) - set(frames))
    if missing:
        raise ValueError(
            ".stack_sizes is missing %d functions, including %s"
            % (len(missing), ", ".join(missing[:5]))
        )
    return frames


def analyze_artifact(path, entries, max_path_bytes):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise ValueError("pyelftools 0.32 is required: %s" % error)

    with open(path, "rb") as artifact:
        elf = ELFFile(artifact)
        if elf["e_machine"] != "EM_BPF":
            raise ValueError("artifact is not an EM_BPF ELF object")
        symtab, functions, by_location = _function_symbols(elf)
        relocations = _relocations_by_target_section(elf)
        frames = read_stack_frames(elf, symtab, functions, by_location)
        calls = read_call_graph(elf, functions, by_location, relocations)
        reports = validate_budget(entries, frames, calls, max_path_bytes)

    return {
        "artifact": os.path.basename(path),
        "max_path_bytes": max_path_bytes,
        "entries": reports,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--max-path-bytes", type=int, default=448)
    parser.add_argument("--report")
    parser.add_argument("--entry", action="append", dest="entries")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    entries = tuple(args.entries or DEFAULT_ENTRIES)
    try:
        report = analyze_artifact(args.artifact, entries, args.max_path_bytes)
    except (BudgetExceeded, OSError, ValueError) as error:
        print("eBPF stack budget check failed: %s" % error, file=sys.stderr)
        return 1

    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
