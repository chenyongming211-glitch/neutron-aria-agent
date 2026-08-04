use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_link_info, bpf_link_type};
use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XdpPinnedLinkIdentity {
    pub(crate) link_type: u32,
    pub(crate) link_id: u32,
    pub(crate) program_id: u32,
    pub(crate) ifindex: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XdpLinkHealthReason {
    MissingProgramPin,
    ProgramUnverifiable,
    MissingLinkPin,
    LinkUnverifiable,
    WrongLinkType,
    InvalidLinkId,
    Detached,
    InterfaceUnverifiable,
    WrongInterface,
    WrongProgram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XdpLinkHealth {
    VerifiedLive {
        link_id: u32,
        program_id: u32,
        ifindex: u32,
    },
    NotReady(XdpLinkHealthReason),
}

impl XdpLinkHealth {
    pub(crate) fn is_ready(self) -> bool {
        match self {
            Self::VerifiedLive {
                link_id,
                program_id,
                ifindex,
            } => link_id != 0 && program_id != 0 && ifindex != 0,
            Self::NotReady(_) => false,
        }
    }

    pub(crate) fn reason(self) -> Option<XdpLinkHealthReason> {
        match self {
            Self::VerifiedLive { .. } => None,
            Self::NotReady(reason) => Some(reason),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExistingXdpPinDisposition {
    Attach,
    Claim,
    PreserveDegraded,
}

pub(crate) fn existing_xdp_pin_disposition(
    pin_exists: bool,
    verified_live: bool,
) -> ExistingXdpPinDisposition {
    match (pin_exists, verified_live) {
        (false, _) => ExistingXdpPinDisposition::Attach,
        (true, true) => ExistingXdpPinDisposition::Claim,
        (true, false) => ExistingXdpPinDisposition::PreserveDegraded,
    }
}

pub(crate) fn classify_xdp_link_identity(
    expected_program_id: u32,
    expected_ifindex: u32,
    observed: XdpPinnedLinkIdentity,
) -> XdpLinkHealth {
    if observed.link_type != bpf_link_type::BPF_LINK_TYPE_XDP as u32 {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongLinkType);
    }
    if observed.link_id == 0 {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::InvalidLinkId);
    }
    if observed.ifindex == 0 {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::Detached);
    }
    if observed.ifindex != expected_ifindex {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongInterface);
    }
    if observed.program_id != expected_program_id {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongProgram);
    }
    XdpLinkHealth::VerifiedLive {
        link_id: observed.link_id,
        program_id: observed.program_id,
        ifindex: observed.ifindex,
    }
}

fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    // SAFETY: `attr` points to a zero-initialized kernel UAPI union whose fields
    // are initialized for `cmd`; the kernel copies from/to it during this call.
    let result = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size_of::<bpf_attr>()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn open_pinned_bpf_object(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pin path contains NUL"))?;
    // SAFETY: all-zero is the required initial state for unused `bpf_attr`
    // fields. The pathname pointer remains valid for the duration of syscall.
    let mut attr = unsafe { zeroed::<bpf_attr>() };
    // SAFETY: BPF_OBJ_GET uses the object-path member of the UAPI union.
    let object = unsafe { &mut attr.__bindgen_anon_4 };
    object.pathname = path.as_ptr() as u64;
    let fd = sys_bpf(bpf_cmd::BPF_OBJ_GET, &mut attr)?;
    let raw_fd = i32::try_from(fd).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "BPF_OBJ_GET returned invalid fd",
        )
    })?;
    // SAFETY: a successful BPF_OBJ_GET returns a new owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

fn read_pinned_link_identity(path: &Path) -> io::Result<XdpPinnedLinkIdentity> {
    let fd = open_pinned_bpf_object(path)?;
    // SAFETY: the kernel UAPI requires zeroed output and attribute structures.
    let mut info = unsafe { zeroed::<bpf_link_info>() };
    let mut attr = unsafe { zeroed::<bpf_attr>() };
    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info_len = size_of::<bpf_link_info>() as u32;
    attr.info.info = (&mut info as *mut bpf_link_info) as u64;
    sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;

    let ifindex = if info.type_ == bpf_link_type::BPF_LINK_TYPE_XDP as u32 {
        // SAFETY: the union's XDP member is valid after verifying link type.
        unsafe { info.__bindgen_anon_1.xdp.ifindex }
    } else {
        0
    };
    Ok(XdpPinnedLinkIdentity {
        link_type: info.type_,
        link_id: info.id,
        program_id: info.prog_id,
        ifindex,
    })
}

fn read_ifindex(iface: &str) -> Result<u32, XdpLinkHealthReason> {
    std::fs::read_to_string(PathBuf::from("/sys/class/net").join(iface).join("ifindex"))
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|ifindex| *ifindex != 0)
        .ok_or(XdpLinkHealthReason::InterfaceUnverifiable)
}

pub(crate) fn exact_xdp_link_health(
    iface: &str,
    program_pin: &Path,
    link_pin: &Path,
) -> XdpLinkHealth {
    if !program_pin.exists() {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::MissingProgramPin);
    }
    let program = match aya::programs::Xdp::from_pin(
        program_pin,
        aya_obj::programs::XdpAttachType::Interface,
    ) {
        Ok(program) => program,
        Err(_) => return XdpLinkHealth::NotReady(XdpLinkHealthReason::ProgramUnverifiable),
    };
    let expected_program_id = match program.info() {
        Ok(info) => info.id(),
        Err(_) => return XdpLinkHealth::NotReady(XdpLinkHealthReason::ProgramUnverifiable),
    };
    if !link_pin.exists() {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::MissingLinkPin);
    }
    let observed = match read_pinned_link_identity(link_pin) {
        Ok(observed) => observed,
        Err(_) => return XdpLinkHealth::NotReady(XdpLinkHealthReason::LinkUnverifiable),
    };
    let expected_ifindex = match read_ifindex(iface) {
        Ok(ifindex) => ifindex,
        Err(reason) => return XdpLinkHealth::NotReady(reason),
    };
    classify_xdp_link_identity(expected_program_id, expected_ifindex, observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        link_type: u32,
        link_id: u32,
        program_id: u32,
        ifindex: u32,
    ) -> XdpPinnedLinkIdentity {
        XdpPinnedLinkIdentity {
            link_type,
            link_id,
            program_id,
            ifindex,
        }
    }

    #[test]
    fn xdp_link_identity_requires_exact_live_program_and_interface() {
        let health = classify_xdp_link_identity(41, 9, identity(6, 77, 41, 9));
        assert_eq!(
            health,
            XdpLinkHealth::VerifiedLive {
                link_id: 77,
                program_id: 41,
                ifindex: 9,
            }
        );
        assert!(health.is_ready());
    }

    #[test]
    fn xdp_link_identity_rejects_detached_but_pinned_link() {
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 77, 41, 0)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::Detached),
        );
    }

    #[test]
    fn xdp_link_identity_rejects_wrong_interface_program_type_and_zero_id() {
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 77, 41, 10)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongInterface),
        );
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 77, 42, 9)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongProgram),
        );
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(11, 77, 41, 9)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongLinkType),
        );
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 0, 41, 9)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::InvalidLinkId),
        );
    }

    #[test]
    fn xdp_link_identity_unavailable_evidence_is_never_ready() {
        for reason in [
            XdpLinkHealthReason::MissingProgramPin,
            XdpLinkHealthReason::ProgramUnverifiable,
            XdpLinkHealthReason::MissingLinkPin,
            XdpLinkHealthReason::LinkUnverifiable,
            XdpLinkHealthReason::InterfaceUnverifiable,
        ] {
            assert!(!XdpLinkHealth::NotReady(reason).is_ready());
        }
    }

    #[test]
    fn xdp_link_identity_existing_unverified_pin_is_preserved_not_replaced() {
        assert_eq!(
            existing_xdp_pin_disposition(true, true),
            ExistingXdpPinDisposition::Claim,
        );
        assert_eq!(
            existing_xdp_pin_disposition(false, false),
            ExistingXdpPinDisposition::Attach,
        );
        assert_eq!(
            existing_xdp_pin_disposition(true, false),
            ExistingXdpPinDisposition::PreserveDegraded,
        );
    }
}
