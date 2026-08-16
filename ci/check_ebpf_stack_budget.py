#!/usr/bin/env python3
"""Enforce a combined BPF call-path stack budget on a linked ELF artifact."""

from __future__ import print_function

import argparse
from collections import deque
import json
import os
import struct
import sys


BPF_CALL_OPCODE = 0x85
BPF_PSEUDO_CALL = 1
DEFAULT_ENTRIES = ("tc_ingress", "tc_egress")
MAX_TRACKED_STACK_OFFSETS = 32


class BudgetExceeded(ValueError):
    pass


def verifier_frame_bytes(frame_bytes):
    return ((max(frame_bytes, 1) + 31) // 32) * 32


def analyze_function_stack(data, function_name):
    if len(data) % 8 != 0:
        raise ValueError("invalid BPF instruction length for %s" % function_name)

    instructions = []
    for offset in range(0, len(data), 8):
        opcode, registers, branch_offset, immediate = struct.unpack_from(
            "<BBhi", data, offset
        )
        instructions.append(
            (
                opcode,
                registers & 0x0F,
                registers >> 4,
                branch_offset,
                immediate,
            )
        )

    if not instructions:
        return 0

    initial = [frozenset() for _ in range(11)]
    initial[10] = frozenset((0,))
    states = {0: tuple(initial)}
    pending = deque((0,))
    depth = 0

    def record_offsets(offsets):
        nonlocal depth
        for stack_offset in offsets:
            if stack_offset < 0:
                depth = max(depth, -stack_offset)

    def merge_states(current, incoming):
        merged = []
        for current_offsets, incoming_offsets in zip(current, incoming):
            offsets = current_offsets | incoming_offsets
            if len(offsets) > MAX_TRACKED_STACK_OFFSETS:
                raise ValueError(
                    "too many frame-pointer states while analyzing %s" % function_name
                )
            merged.append(frozenset(offsets))
        return tuple(merged)

    while pending:
        pc = pending.popleft()
        registers = list(states[pc])
        opcode, destination, source, branch_offset, immediate = instructions[pc]
        instruction_class = opcode & 0x07
        operation = opcode & 0xF0
        register_source = opcode & 0x08

        base_register = None
        if instruction_class == 0x01:  # BPF_LDX
            base_register = source
        elif instruction_class in (0x02, 0x03):  # BPF_ST / BPF_STX
            base_register = destination
        if base_register is not None:
            record_offsets(
                origin + branch_offset for origin in registers[base_register]
            )

        successors = []
        if instruction_class in (0x04, 0x07):  # BPF_ALU / BPF_ALU64
            if operation == 0xB0:  # BPF_MOV
                registers[destination] = (
                    registers[source] if register_source else frozenset()
                )
            elif operation in (0x00, 0x10) and not register_source:  # ADD / SUB imm
                delta = immediate if operation == 0x00 else -immediate
                registers[destination] = frozenset(
                    value + delta for value in registers[destination]
                )
                record_offsets(registers[destination])
            else:
                registers[destination] = frozenset()
            successors = [pc + 1]
        elif instruction_class == 0x01:  # BPF_LDX
            registers[destination] = frozenset()
            successors = [pc + 1]
        elif instruction_class == 0x00:  # BPF_LD / LD_IMM64
            registers[destination] = frozenset()
            successors = [pc + 2 if opcode == 0x18 else pc + 1]
        elif instruction_class in (0x05, 0x06):  # BPF_JMP / BPF_JMP32
            if operation == 0x80:  # BPF_CALL
                for register in range(6):
                    registers[register] = frozenset()
                successors = [pc + 1]
            elif operation == 0x90:  # BPF_EXIT
                successors = []
            elif operation == 0x00:  # BPF_JA
                successors = [pc + 1 + branch_offset]
            else:
                successors = [pc + 1, pc + 1 + branch_offset]
        else:
            successors = [pc + 1]

        outgoing = tuple(registers)
        for successor in successors:
            if successor < 0 or successor >= len(instructions):
                continue
            if successor not in states:
                states[successor] = outgoing
                pending.append(successor)
                continue
            merged = merge_states(states[successor], outgoing)
            if merged != states[successor]:
                states[successor] = merged
                pending.append(successor)

    return depth


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

        result = (
            verifier_frame_bytes(frames[name]) + best_child_total,
            [name] + best_child_path,
        )
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
                {
                    "function": function,
                    "frame_bytes": frames[function],
                    "verifier_bytes": verifier_frame_bytes(frames[function]),
                }
                for function in path
            ],
        }
        if total > max_path_bytes:
            rendered_path = " -> ".join(
                "%s(raw=%d, verifier=%d)"
                % (
                    frame["function"],
                    frame["frame_bytes"],
                    frame["verifier_bytes"],
                )
                for frame in reports[entry]["path"]
            )
            raise BudgetExceeded(
                "%s call path uses %d bytes exceeds %d byte budget: %s"
                % (entry, total, max_path_bytes, rendered_path)
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


def read_stack_frames(elf, functions):
    frames = {}
    for name, function in functions.items():
        section = elf.get_section(function["section_index"])
        start = function["value"]
        end = start + function["size"]
        data = section.data()
        if end > len(data):
            raise ValueError("invalid BPF function range for %s" % name)
        frames[name] = analyze_function_stack(
            data[start:end],
            name,
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
        frames = read_stack_frames(elf, functions)
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
    parser.add_argument("--max-path-bytes", type=int, default=480)
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
