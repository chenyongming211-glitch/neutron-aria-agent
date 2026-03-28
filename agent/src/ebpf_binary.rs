use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TraceBackendKind {
    LegacyMap,
    PerfEventArray,
    RingBuf,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TraceBackendPreference {
    Auto,
    LegacyMap,
    PerfEventArray,
    RingBuf,
}

impl TraceBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyMap => "legacy-map",
            Self::PerfEventArray => "perf-event-array",
            Self::RingBuf => "ringbuf",
        }
    }
}

impl TraceBackendPreference {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "legacy" | "legacy-map" => Ok(Self::LegacyMap),
            "perf" | "perf-event" | "perf-event-array" => Ok(Self::PerfEventArray),
            "ringbuf" => Ok(Self::RingBuf),
            other => Err(format!(
                "invalid trace backend preference '{}': expected auto, legacy-map, perf-event-array, or ringbuf",
                other
            )),
        }
    }
}

impl fmt::Display for TraceBackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct KernelVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl KernelVersion {
    fn supports_ringbuf(self) -> bool {
        self.major > 5 || (self.major == 5 && self.minor >= 8)
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedEbpfBinary {
    pub requested_path: String,
    pub selected_path: String,
    pub trace_backend: TraceBackendKind,
    pub kernel_version: Option<String>,
}

pub fn resolve_ebpf_binary(
    requested_path: &str,
    preference: TraceBackendPreference,
) -> Result<ResolvedEbpfBinary, String> {
    let requested = Path::new(requested_path);
    let explicit_backend = explicit_backend_from_path(requested);

    let (selected_path, trace_backend) = if let Some(kind) = explicit_backend {
        if !requested.exists() {
            return Err(format!(
                "configured eBPF binary '{}' does not exist",
                requested.display()
            ));
        }
        (requested.to_path_buf(), kind)
    } else {
        let ringbuf_path = sibling_variant_path(requested, "_ringbuf")?;
        let perf_path = sibling_variant_path(requested, "_perf")?;
        let kernel_version = current_kernel_version();
        match preference {
            TraceBackendPreference::Auto => {
                if matches!(kernel_version, Some(version) if version.supports_ringbuf())
                    && ringbuf_path.exists()
                {
                    (ringbuf_path, TraceBackendKind::RingBuf)
                } else if perf_path.exists() {
                    (perf_path, TraceBackendKind::PerfEventArray)
                } else if requested.exists() {
                    (requested.to_path_buf(), TraceBackendKind::LegacyMap)
                } else {
                    return Err(format!(
                        "eBPF binary not found: checked '{}', '{}' and '{}'",
                        requested.display(),
                        ringbuf_path.display(),
                        perf_path.display()
                    ));
                }
            }
            TraceBackendPreference::LegacyMap => {
                if requested.exists() {
                    (requested.to_path_buf(), TraceBackendKind::LegacyMap)
                } else {
                    return Err(format!(
                        "preferred legacy-map backend not found at '{}'",
                        requested.display()
                    ));
                }
            }
            TraceBackendPreference::PerfEventArray => {
                if perf_path.exists() {
                    (perf_path, TraceBackendKind::PerfEventArray)
                } else {
                    return Err(format!(
                        "preferred perf-event-array backend not found at '{}'",
                        perf_path.display()
                    ));
                }
            }
            TraceBackendPreference::RingBuf => {
                if matches!(kernel_version, Some(version) if !version.supports_ringbuf()) {
                    return Err(format!(
                        "preferred ringbuf backend requires kernel >= 5.8 but found '{}'",
                        kernel_version
                            .map(kernel_version_string)
                            .unwrap_or_else(|| "unknown".to_string())
                    ));
                }
                if ringbuf_path.exists() {
                    (ringbuf_path, TraceBackendKind::RingBuf)
                } else {
                    return Err(format!(
                        "preferred ringbuf backend not found at '{}'",
                        ringbuf_path.display()
                    ));
                }
            }
        }
    };

    Ok(ResolvedEbpfBinary {
        requested_path: requested_path.to_string(),
        selected_path: selected_path.to_string_lossy().to_string(),
        trace_backend,
        kernel_version: current_kernel_version().map(kernel_version_string),
    })
}

fn explicit_backend_from_path(path: &Path) -> Option<TraceBackendKind> {
    let stem = path.file_stem()?.to_str()?;
    if stem.ends_with("_ringbuf") {
        Some(TraceBackendKind::RingBuf)
    } else if stem.ends_with("_perf") {
        Some(TraceBackendKind::PerfEventArray)
    } else {
        None
    }
}

fn sibling_variant_path(path: &Path, suffix: &str) -> Result<PathBuf, String> {
    let stem = path.file_stem().and_then(|value| value.to_str()).ok_or_else(|| {
        format!(
            "cannot derive eBPF variant path from '{}'",
            path.display()
        )
    })?;

    let mut filename = format!("{}{}", stem, suffix);
    if let Some(ext) = path.extension().and_then(|value| value.to_str()) {
        filename.push('.');
        filename.push_str(ext);
    }

    Ok(path.with_file_name(filename))
}

fn current_kernel_version() -> Option<KernelVersion> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    parse_kernel_version(raw.trim())
}

fn parse_kernel_version(raw: &str) -> Option<KernelVersion> {
    let release = raw.split('-').next().unwrap_or(raw);
    let mut parts = release.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()
        .and_then(|value| {
            let digits: String = value.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                None
            } else {
                digits.parse().ok()
            }
        })
        .unwrap_or(0);
    Some(KernelVersion {
        major,
        minor,
        patch,
    })
}

fn kernel_version_string(version: KernelVersion) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}
