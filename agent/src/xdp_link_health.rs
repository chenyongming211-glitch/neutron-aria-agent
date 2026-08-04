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
