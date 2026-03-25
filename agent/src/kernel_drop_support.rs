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

pub fn resolve_kernel_drop_config() -> Result<KernelDropConfig, String> {
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

    Ok(KernelDropConfig {
        flags,
        trace_skbaddr_offset: trace_format.skbaddr_offset,
        trace_location_offset: trace_format.location_offset.unwrap_or(0),
        trace_protocol_offset: trace_format.protocol_offset.unwrap_or(0),
        trace_reason_offset: trace_format.reason_offset.unwrap_or(0),
        skb_dev_offset,
        skb_len_offset,
        net_device_ifindex_offset,
    })
}

struct TracepointFormatOffsets {
    skbaddr_offset: u32,
    location_offset: Option<u32>,
    protocol_offset: Option<u32>,
    reason_offset: Option<u32>,
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
        let mut offset = 0usize;
        while offset + 12 <= self.types.len() {
            let name_off = read_u32(&self.types, offset)?;
            let info = read_u32(&self.types, offset + 4)?;
            let _size_or_type = read_u32(&self.types, offset + 8)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let kind_flag = (info >> 31) != 0;
            let record_size = record_size(kind, vlen)?;

            if offset + record_size > self.types.len() {
                return Err("kernel BTF type record exceeds type section".to_string());
            }

            if kind == BTF_KIND_STRUCT {
                let name = self.string(name_off)?;
                if name == struct_name {
                    let members_base = offset + 12;
                    for member_index in 0..vlen {
                        let member_offset = members_base + member_index * 12;
                        let member_name_off = read_u32(&self.types, member_offset)?;
                        let raw_bit_offset = read_u32(&self.types, member_offset + 8)?;
                        let member = self.string(member_name_off)?;
                        if member != member_name {
                            continue;
                        }

                        let bit_offset = if kind_flag {
                            raw_bit_offset & 0x00ff_ffff
                        } else {
                            raw_bit_offset
                        };
                        if bit_offset % 8 != 0 {
                            return Err(format!(
                                "BTF member {}.{} has non-byte-aligned offset {}",
                                struct_name, member_name, bit_offset
                            ));
                        }
                        return Ok(bit_offset / 8);
                    }

                    return Err(format!(
                        "BTF struct {} missing member {}",
                        struct_name, member_name
                    ));
                }
            }

            offset += record_size;
        }

        Err(format!("BTF struct {} not found", struct_name))
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
