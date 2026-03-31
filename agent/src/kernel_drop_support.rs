use std::path::{Path, PathBuf};

use aria_core::common::{
    KernelDropConfig, KERNEL_DROP_FLAG_HAS_LOCATION, KERNEL_DROP_FLAG_HAS_PROTOCOL,
    KERNEL_DROP_FLAG_HAS_REASON,
};
use regex::Regex;

pub const KERNEL_DROP_TRACEPOINT_CATEGORY: &str = "skb";
pub const KERNEL_DROP_TRACEPOINT_NAME: &str = "kfree_skb";
pub const KERNEL_DROP_PROGRAM_NAME: &str = "kernel_drop_trace";
pub const KERNEL_DROP_LINK_NAME: &str = "kernel_drop_trace_link";
pub const KERNEL_DROP_MAP_NAMES: &[&str] = &[
    "MANAGED_IFINDEX_FILTER",
    "KERNEL_DROP_CONFIG",
    "KERNEL_DROP_STATS",
    "KERNEL_DROP_VALUE_BUF",
];

const TRACEFS_FORMAT_PATHS: &[&str] = &[
    "/sys/kernel/tracing/events/skb/kfree_skb/format",
    "/sys/kernel/debug/tracing/events/skb/kfree_skb/format",
];
const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_ENUM64: u32 = 19;

pub fn pin_map_if_needed(
    bpf: &mut aya::Ebpf,
    map_name: &str,
    pin_path: &str,
) -> Result<(), String> {
    let target = format!("{}/{}", pin_path, map_name);
    if Path::new(&target).exists() {
        return Ok(());
    }

    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| format!("{} map not found in eBPF binary", map_name))?;

    map.pin(&target)
        .map_err(|e| format!("{} pin: {}", map_name, e))
}

fn tracepoint_program<'a>(
    bpf: &'a mut aya::Ebpf,
    prog_name: &str,
) -> Result<&'a mut aya::programs::TracePoint, String> {
    let program = bpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found in eBPF binary", prog_name))?;

    program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("{} try_into: {:?}", prog_name, e))
}

fn is_already_loaded_error(err: &str) -> bool {
    let normalized = err.to_ascii_lowercase();
    normalized.contains("already loaded") || normalized.contains("alreadyloaded")
}

pub fn load_tracepoint_program(bpf: &mut aya::Ebpf, prog_name: &str) -> Result<(), String> {
    let program = tracepoint_program(bpf, prog_name)?;
    match program.load() {
        Ok(()) => Ok(()),
        Err(e) => {
            let err = format!("{:?}", e);
            if is_already_loaded_error(&err) {
                Ok(())
            } else {
                Err(format!("{} load: {}", prog_name, err))
            }
        }
    }
}

pub fn pin_program_if_needed(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    pin_path: &str,
) -> Result<(), String> {
    let target = format!("{}/{}", pin_path, prog_name);
    if Path::new(&target).exists() {
        return Ok(());
    }

    let program = bpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found in eBPF binary", prog_name))?;

    program
        .pin(&target)
        .map_err(|e| format!("{} pin: {:?}", prog_name, e))
}

pub fn replace_pinned_program(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    pin_path: &str,
) -> Result<(), String> {
    let target = format!("{}/{}", pin_path, prog_name);
    if Path::new(&target).exists() {
        std::fs::remove_file(&target)
            .map_err(|e| format!("{} remove old pin {}: {}", prog_name, target, e))?;
    }

    let program = bpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found in eBPF binary", prog_name))?;

    program
        .pin(&target)
        .map_err(|e| format!("{} pin: {:?}", prog_name, e))
}

pub fn attach_tracepoint_if_needed(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
    pin_path: &str,
) -> Result<(), String> {
    let link_pin = format!("{}/{}", pin_path, KERNEL_DROP_LINK_NAME);
    if Path::new(&link_pin).exists() {
        return Ok(());
    }

    let program = tracepoint_program(bpf, prog_name)?;
    match program.load() {
        Ok(()) => {}
        Err(e) => {
            let err = format!("{:?}", e);
            if !is_already_loaded_error(&err) {
                return Err(format!("{} load: {}", prog_name, err));
            }
        }
    }

    let link_id = program
        .attach(category, name)
        .map_err(|e| format!("{} attach {}/{}: {:?}", prog_name, category, name, e))?;

    let link = program
        .take_link(link_id)
        .map_err(|e| format!("{} take_link: {:?}", prog_name, e))?;
    let fd_link: aya::programs::links::FdLink = link
        .try_into()
        .map_err(|e: aya::programs::links::LinkError| format!("{} FdLink: {:?}", prog_name, e))?;
    fd_link
        .pin(&link_pin)
        .map_err(|e| format!("{} pin link: {:?}", prog_name, e))?;

    Ok(())
}

pub fn replace_pinned_tracepoint_link(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
    pin_path: &str,
) -> Result<(), String> {
    let link_pin = format!("{}/{}", pin_path, KERNEL_DROP_LINK_NAME);
    let program = tracepoint_program(bpf, prog_name)?;
    match program.load() {
        Ok(()) => {}
        Err(e) => {
            let err = format!("{:?}", e);
            if !is_already_loaded_error(&err) {
                return Err(format!("{} load: {}", prog_name, err));
            }
        }
    }

    if Path::new(&link_pin).exists() {
        std::fs::remove_file(&link_pin)
            .map_err(|e| format!("{} remove old link {}: {}", prog_name, link_pin, e))?;
    }

    let link_id = program
        .attach(category, name)
        .map_err(|e| format!("{} attach {}/{}: {:?}", prog_name, category, name, e))?;

    let link = program
        .take_link(link_id)
        .map_err(|e| format!("{} take_link: {:?}", prog_name, e))?;
    let fd_link: aya::programs::links::FdLink = link
        .try_into()
        .map_err(|e: aya::programs::links::LinkError| format!("{} FdLink: {:?}", prog_name, e))?;
    fd_link
        .pin(&link_pin)
        .map_err(|e| format!("{} pin link: {:?}", prog_name, e))?;

    Ok(())
}

pub fn resolve_kernel_drop_config() -> Result<(KernelDropConfig, std::collections::HashMap<u16, String>), String> {
    let trace_format = parse_tracepoint_format()?;
    let btf = BtfBlob::load(Path::new(KERNEL_BTF_PATH))?;

    let skb_dev_offset = btf.find_struct_member_offset("sk_buff", "dev")?;
    let skb_len_offset = btf.find_struct_member_offset("sk_buff", "len")?;
    let net_device_ifindex_offset = btf.find_struct_member_offset("net_device", "ifindex")?;

    let mut flags = 0u32;
    if trace_format.protocol_offset.is_some() {
        flags |= KERNEL_DROP_FLAG_HAS_PROTOCOL;
    }
    if trace_format.location_offset.is_some() {
        flags |= KERNEL_DROP_FLAG_HAS_LOCATION;
    }
    if trace_format.reason_offset.is_some() {
        flags |= KERNEL_DROP_FLAG_HAS_REASON;
    }

    let config = KernelDropConfig {
        flags,
        trace_skbaddr_offset: trace_format.skbaddr_offset,
        trace_location_offset: trace_format.location_offset.unwrap_or(0),
        trace_protocol_offset: trace_format.protocol_offset.unwrap_or(0),
        trace_reason_offset: trace_format.reason_offset.unwrap_or(0),
        skb_dev_offset,
        skb_len_offset,
        net_device_ifindex_offset,
    };

    Ok((config, trace_format.reason_names))
}

struct TracepointFormatOffsets {
    skbaddr_offset: u32,
    location_offset: Option<u32>,
    protocol_offset: Option<u32>,
    reason_offset: Option<u32>,
    reason_names: std::collections::HashMap<u16, String>,
}

fn parse_tracepoint_format() -> Result<TracepointFormatOffsets, String> {
    let path = TRACEFS_FORMAT_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .ok_or_else(|| {
            format!(
                "tracepoint format for {}/{} not found in {:?}",
                KERNEL_DROP_TRACEPOINT_CATEGORY, KERNEL_DROP_TRACEPOINT_NAME, TRACEFS_FORMAT_PATHS
            )
        })?;

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("read tracepoint format {}: {}", path.display(), e))?;
    let field_re =
        Regex::new(r"field:[^;]*\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*offset:(?P<offset>\d+)")
            .map_err(|e| format!("compile tracepoint field regex: {}", e))?;

    let mut offsets = TracepointFormatOffsets {
        skbaddr_offset: 0,
        location_offset: None,
        protocol_offset: None,
        reason_offset: None,
        reason_names: std::collections::HashMap::new(),
    };
    let mut saw_skbaddr = false;

    for line in raw.lines() {
        let Some(captures) = field_re.captures(line) else {
            continue;
        };

        let name = captures
            .name("name")
            .map(|m| m.as_str())
            .unwrap_or_default();
        let offset: u32 = captures
            .name("offset")
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .ok_or_else(|| format!("invalid tracepoint offset line: {}", line))?;

        match name {
            "skbaddr" => {
                offsets.skbaddr_offset = offset;
                saw_skbaddr = true;
            }
            "location" => offsets.location_offset = Some(offset),
            "protocol" => offsets.protocol_offset = Some(offset),
            "reason" => offsets.reason_offset = Some(offset),
            _ => {}
        }
    }

    if !saw_skbaddr {
        return Err(format!(
            "tracepoint format {} missing skbaddr field",
            path.display()
        ));
    }

    // Parse __print_symbolic(REC->reason, { N, "NAME" }, ...) for reason name mapping.
    let symbolic_re = Regex::new(r#"\{\s*(\d+)\s*,\s*"([^"]+)"\s*\}"#)
        .map_err(|e| format!("compile symbolic regex: {}", e))?;
    for captures in symbolic_re.captures_iter(&raw) {
        if let (Some(val_match), Some(name_match)) = (captures.get(1), captures.get(2)) {
            if let Ok(val) = val_match.as_str().parse::<u16>() {
                offsets
                    .reason_names
                    .insert(val, name_match.as_str().to_lowercase());
            }
        }
    }

    Ok(offsets)
}

struct BtfBlob {
    types: Vec<u8>,
    strings: Vec<u8>,
}

impl BtfBlob {
    fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read(path)
            .map_err(|e| format!("read kernel BTF {}: {}", path.display(), e))?;
        if raw.len() < 24 {
            return Err(format!("kernel BTF {} is too small", path.display()));
        }

        let magic = read_u16(&raw, 0)?;
        if magic != 0xeb9f {
            return Err(format!(
                "kernel BTF {} has unsupported magic 0x{:04x}",
                path.display(),
                magic
            ));
        }

        let version = raw[2];
        if version != 1 {
            return Err(format!(
                "kernel BTF {} has unsupported version {}",
                path.display(),
                version
            ));
        }

        let hdr_len = read_u32(&raw, 4)? as usize;
        let type_off = read_u32(&raw, 8)? as usize;
        let type_len = read_u32(&raw, 12)? as usize;
        let str_off = read_u32(&raw, 16)? as usize;
        let str_len = read_u32(&raw, 20)? as usize;

        let types_start = hdr_len + type_off;
        let strings_start = hdr_len + str_off;
        let types_end = types_start
            .checked_add(type_len)
            .ok_or_else(|| "kernel BTF type section overflow".to_string())?;
        let strings_end = strings_start
            .checked_add(str_len)
            .ok_or_else(|| "kernel BTF string section overflow".to_string())?;

        if types_end > raw.len() || strings_end > raw.len() {
            return Err(format!(
                "kernel BTF {} sections exceed file size",
                path.display()
            ));
        }

        Ok(Self {
            types: raw[types_start..types_end].to_vec(),
            strings: raw[strings_start..strings_end].to_vec(),
        })
    }

    fn find_struct_member_offset(
        &self,
        struct_name: &str,
        member_name: &str,
    ) -> Result<u32, String> {
        // Build a type_id -> byte_offset_in_types index for fast lookup.
        // BTF type IDs start at 1; index[0] is unused.
        let type_offsets = self.build_type_offset_index();

        // Find the named struct first.
        let struct_type_offset = self.find_named_type(struct_name, BTF_KIND_STRUCT)?;

        // Then recursively search its members (including anonymous union/struct).
        self.search_members_recursive(struct_type_offset, member_name, 0, &type_offsets)
            .and_then(|result| {
                result.ok_or_else(|| {
                    format!("BTF struct {} missing member {}", struct_name, member_name)
                })
            })
    }

    /// Build a vec mapping BTF type_id -> byte offset in self.types.
    /// type_id 0 is void (no entry), type_id 1 is the first record.
    fn build_type_offset_index(&self) -> Vec<usize> {
        let mut index = vec![0usize]; // index[0] = void placeholder
        let mut offset = 0usize;
        while offset + 12 <= self.types.len() {
            let Ok(info) = read_u32(&self.types, offset + 4) else { break };
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let Ok(rs) = record_size(kind, vlen) else { break };
            if offset + rs > self.types.len() {
                break;
            }
            index.push(offset);
            offset += rs;
        }
        index
    }

    /// Find the byte offset in self.types of a named type with the given kind.
    /// Skips forward declarations (vlen=0 for struct/union) to find the full definition.
    fn find_named_type(&self, name: &str, kind: u32) -> Result<usize, String> {
        let mut offset = 0usize;
        let mut found: Option<usize> = None;
        while offset + 12 <= self.types.len() {
            let Ok(name_off) = read_u32(&self.types, offset) else { break };
            let Ok(info) = read_u32(&self.types, offset + 4) else { break };
            let k = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let Ok(rs) = record_size(k, vlen) else { break };
            if offset + rs > self.types.len() {
                break;
            }
            if k == kind {
                if let Ok(n) = self.string(name_off) {
                    if n == name {
                        // Prefer the full definition (vlen > 0) over a forward declaration.
                        if vlen > 0 {
                            return Ok(offset);
                        } else if found.is_none() {
                            found = Some(offset);
                        }
                    }
                }
            }
            offset += rs;
        }
        found.ok_or_else(|| format!("BTF struct {} not found", name))
    }

    /// Recursively search members of a struct/union at `type_offset` for `member_name`.
    /// `base_bit_offset` is the accumulated bit offset of the parent within the root struct.
    /// Returns Ok(Some(byte_offset)) if found, Ok(None) if not found in this type.
    fn search_members_recursive(
        &self,
        type_offset: usize,
        member_name: &str,
        base_bit_offset: u32,
        type_offsets: &[usize],
    ) -> Result<Option<u32>, String> {
        let info = read_u32(&self.types, type_offset + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let kind_flag = (info >> 31) != 0;

        if kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION {
            return Ok(None);
        }

        let members_base = type_offset + 12;
        for i in 0..vlen {
            let member_off = members_base + i * 12;
            let member_name_off = read_u32(&self.types, member_off)?;
            let member_type_id = read_u32(&self.types, member_off + 4)?;
            let raw_bit_offset = read_u32(&self.types, member_off + 8)?;

            let bit_offset = if kind_flag {
                raw_bit_offset & 0x00ff_ffff
            } else {
                raw_bit_offset
            };
            let abs_bit_offset = base_bit_offset + bit_offset;

            let mname = self.string(member_name_off)?;

            if mname == member_name {
                // Found it.
                if abs_bit_offset % 8 != 0 {
                    return Err(format!(
                        "BTF member {} has non-byte-aligned offset {}",
                        member_name, abs_bit_offset
                    ));
                }
                return Ok(Some(abs_bit_offset / 8));
            }

            // If this member is anonymous (empty name) and is a struct/union,
            // recurse into it.
            if mname.is_empty() {
                let nested_type_offset = self.resolve_type_offset(member_type_id, type_offsets);
                if let Some(nested_offset) = nested_type_offset {
                    if let Some(found) = self.search_members_recursive(
                        nested_offset,
                        member_name,
                        abs_bit_offset,
                        type_offsets,
                    )? {
                        return Ok(Some(found));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Resolve a type_id to its byte offset in self.types, following TYPEDEF/CONST/VOLATILE/RESTRICT.
    fn resolve_type_offset(&self, type_id: u32, type_offsets: &[usize]) -> Option<usize> {
        // BTF modifier kinds that wrap another type
        const BTF_KIND_TYPEDEF: u32 = 8;
        const BTF_KIND_VOLATILE: u32 = 9;
        const BTF_KIND_CONST: u32 = 10;
        const BTF_KIND_RESTRICT: u32 = 11;

        let mut current_id = type_id;
        for _ in 0..32 {
            let idx = current_id as usize;
            if idx == 0 || idx >= type_offsets.len() {
                return None;
            }
            let off = type_offsets[idx];
            let Ok(info) = read_u32(&self.types, off + 4) else { return None };
            let kind = (info >> 24) & 0x1f;
            match kind {
                BTF_KIND_STRUCT | BTF_KIND_UNION => return Some(off),
                BTF_KIND_TYPEDEF | BTF_KIND_VOLATILE | BTF_KIND_CONST | BTF_KIND_RESTRICT => {
                    // size_or_type field holds the wrapped type_id
                    let Ok(next_id) = read_u32(&self.types, off + 8) else { return None };
                    current_id = next_id;
                }
                _ => return None,
            }
        }
        None
    }

    fn string(&self, offset: u32) -> Result<&str, String> {
        let start = offset as usize;
        if start >= self.strings.len() {
            return Err(format!("BTF string offset {} out of bounds", offset));
        }

        let end = self.strings[start..]
            .iter()
            .position(|b| *b == 0)
            .map(|idx| start + idx)
            .ok_or_else(|| format!("BTF string offset {} missing terminator", offset))?;
        std::str::from_utf8(&self.strings[start..end])
            .map_err(|e| format!("BTF string offset {} invalid UTF-8: {}", offset, e))
    }
}

fn record_size(kind: u32, vlen: usize) -> Result<usize, String> {
    let extra = match kind {
        BTF_KIND_INT => 4,
        BTF_KIND_ARRAY => 12,
        BTF_KIND_STRUCT | BTF_KIND_UNION => vlen
            .checked_mul(12)
            .ok_or_else(|| "BTF struct/union record size overflow".to_string())?,
        BTF_KIND_ENUM => vlen
            .checked_mul(8)
            .ok_or_else(|| "BTF enum record size overflow".to_string())?,
        BTF_KIND_FUNC_PROTO => vlen
            .checked_mul(8)
            .ok_or_else(|| "BTF func proto record size overflow".to_string())?,
        BTF_KIND_VAR => 4,
        BTF_KIND_DATASEC => vlen
            .checked_mul(12)
            .ok_or_else(|| "BTF datasec record size overflow".to_string())?,
        BTF_KIND_ENUM64 => vlen
            .checked_mul(12)
            .ok_or_else(|| "BTF enum64 record size overflow".to_string())?,
        _ => 0,
    };

    12usize
        .checked_add(extra)
        .ok_or_else(|| "BTF record size overflow".to_string())
}

fn read_u16(buf: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = buf
        .get(offset..offset + 2)
        .ok_or_else(|| format!("read_u16 out of bounds at {}", offset))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = buf
        .get(offset..offset + 4)
        .ok_or_else(|| format!("read_u32 out of bounds at {}", offset))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
