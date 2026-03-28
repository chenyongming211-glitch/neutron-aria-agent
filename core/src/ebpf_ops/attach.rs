use super::*;

/// Setup TC ingress: add clsact qdisc and attach the tc_ingress classifier program (mirror only).
/// The TC link is pinned to `{pin_path}/tc_ingress_link` to prevent detach on drop.
#[allow(dead_code)]
pub fn attach_tc_ingress(bpf: &mut aya::Ebpf, iface: &str, pin_path: &str) -> Result<(), String> {
    if let Err(e) = aya::programs::tc::qdisc_add_clsact(iface) {
        let err_str = format!("{:?}", e);
        if !err_str.contains("File exists") {
            return Err(format!("qdisc_add_clsact failed: {}", err_str));
        }
    }

    let tc_program = bpf
        .program_mut("tc_ingress")
        .ok_or("TC ingress program not found")?;

    let tc: &mut aya::programs::SchedClassifier = tc_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("tc_ingress try_into error: {:?}", e))?;

    tc.load()
        .map_err(|e| format!("tc_ingress.load error: {:?}", e))?;

    let link_id = tc
        .attach(iface, aya::programs::tc::TcAttachType::Ingress)
        .map_err(|e| format!("tc_ingress attach error: {:?}", e))?;

    let tc_link = tc
        .take_link(link_id)
        .map_err(|e| format!("tc_ingress take_link error: {:?}", e))?;
    let fd_link: aya::programs::links::FdLink =
        tc_link.try_into().map_err(|e: aya::programs::links::LinkError| {
            format!("tc_ingress convert to FdLink error: {:?}", e)
        })?;
    let tc_link_pin = format!("{}/tc_ingress_link", pin_path);
    let _pinned = fd_link
        .pin(&tc_link_pin)
        .map_err(|e| format!("tc_ingress pin link error: {:?}", e))?;

    info!(iface = %iface, "TC ingress attached with pinned link");
    Ok(())
}

/// Setup TC egress: add clsact qdisc and attach the classifier program.
/// The TC link is pinned to `{pin_path}/tc_egress_link` to prevent detach on drop.
#[allow(dead_code)]
pub fn attach_tc_egress(bpf: &mut aya::Ebpf, iface: &str, pin_path: &str) -> Result<(), String> {
    if let Err(e) = aya::programs::tc::qdisc_add_clsact(iface) {
        let err_str = format!("{:?}", e);
        if !err_str.contains("File exists") {
            return Err(format!("qdisc_add_clsact failed: {}", err_str));
        }
    }

    let tc_program = bpf
        .program_mut("tc_egress")
        .ok_or("TC egress program not found")?;

    let tc: &mut aya::programs::SchedClassifier = tc_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("tc try_into error: {:?}", e))?;

    tc.load().map_err(|e| format!("tc.load error: {:?}", e))?;

    let link_id = tc
        .attach(iface, aya::programs::tc::TcAttachType::Egress)
        .map_err(|e| format!("tc attach error: {:?}", e))?;

    let tc_link = tc
        .take_link(link_id)
        .map_err(|e| format!("tc take_link error: {:?}", e))?;
    let fd_link: aya::programs::links::FdLink = tc_link
        .try_into()
        .map_err(|e: aya::programs::links::LinkError| format!("tc convert to FdLink error: {:?}", e))?;
    let tc_link_pin = format!("{}/tc_egress_link", pin_path);
    let _pinned = fd_link
        .pin(&tc_link_pin)
        .map_err(|e| format!("tc pin link error: {:?}", e))?;

    info!(iface = %iface, "TC egress attached with pinned link");
    Ok(())
}

/// Remove TC egress filter and clsact qdisc
pub fn detach_tc_egress(iface: &str) {
    let _ = std::process::Command::new("tc")
        .args(["filter", "del", "dev", iface, "egress"])
        .output();

    let _ = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "clsact"])
        .output();
}

/// Setup FQ qdisc for EDT-based QoS
pub fn setup_fq_qdisc(iface: &str) -> Result<(), String> {
    let output = std::process::Command::new("tc")
        .args(["qdisc", "replace", "dev", iface, "root", "fq"])
        .output()
        .map_err(|e| format!("Failed to run tc: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("tc qdisc replace fq failed: {}", stderr));
    }
    info!(iface = %iface, "FQ qdisc configured");
    Ok(())
}

/// Check if FQ qdisc is currently active on the interface.
pub fn check_fq_qdisc(iface: &str) -> bool {
    let output = std::process::Command::new("tc")
        .args(["qdisc", "show", "dev", iface])
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("fq")
        }
        Err(_) => false,
    }
}
