use aria_ebpf_abi::{
    fragment_context_disposition, FragmentContextDisposition, FragmentContextKey4,
    FragmentContextValue,
};

fn current_value() -> FragmentContextValue {
    FragmentContextValue {
        src_port: 40000,
        dst_port: 53,
        first_payload_end: 1480,
        acl_bank: 0,
        flags: 0,
        version: 1,
        _pad: 0,
        _reserved: [0; 6],
        epoch: 7,
        expires_at_ns: 30_000_000_000,
    }
}

#[test]
fn fragment_context_key4_has_exact_fragment_identity_layout() {
    let key = FragmentContextKey4 {
        tap_id: 77,
        src_ip: 0xc000_020a,
        dst_ip: 0xc633_6435,
        fragment_id: 0x1234,
        vlan_id: 4094,
        proto: 17,
        direction: 1,
        _pad: [0; 2],
    };

    assert_eq!(core::mem::size_of::<FragmentContextKey4>(), 20);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, tap_id), 0);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, src_ip), 4);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, dst_ip), 8);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, fragment_id), 12);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, vlan_id), 14);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, proto), 16);
    assert_eq!(core::mem::offset_of!(FragmentContextKey4, direction), 17);
    assert_eq!(key.fragment_id, 0x1234);
    assert_eq!((key.vlan_id, key.proto, key.direction), (4094, 17, 1));
}

#[test]
fn fragment_context_value_has_no_implicit_pod_padding() {
    let value = current_value();

    assert_eq!(core::mem::size_of::<FragmentContextValue>(), 32);
    assert_eq!(core::mem::offset_of!(FragmentContextValue, _pad), 9);
    assert_eq!(core::mem::offset_of!(FragmentContextValue, _reserved), 10);
    assert_eq!(core::mem::offset_of!(FragmentContextValue, epoch), 16);
    assert_eq!(value._reserved, [0; 6]);
}

#[test]
fn fragment_context_accepts_current_bank_epoch_and_non_overlapping_offset() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 0, 7, 1_000, 1480),
        FragmentContextDisposition::Hit,
    );
}

#[test]
fn fragment_context_expires_at_the_exact_deadline() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 0, 7, 30_000_000_000, 1480),
        FragmentContextDisposition::Expired,
    );
}

#[test]
fn fragment_context_rejects_overlap_with_first_fragment_range() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 0, 7, 1_000, 1472),
        FragmentContextDisposition::Overlap,
    );
}

#[test]
fn fragment_context_rejects_bank_mismatch() {
    let value = current_value();

    assert_eq!(
        fragment_context_disposition(&value, 1, 7, 1_000, 1480),
        FragmentContextDisposition::Stale,
    );
}

#[test]
fn fragment_context_rejects_two_bank_rotation_epoch_reuse() {
    let value = FragmentContextValue {
        src_port: 40000,
        dst_port: 53,
        first_payload_end: 1480,
        acl_bank: 0,
        flags: 0,
        version: 1,
        _pad: 0,
        _reserved: [0; 6],
        epoch: 7,
        expires_at_ns: 30_000_000_000,
    };
    assert_eq!(
        fragment_context_disposition(&value, 0, 9, 1_000, 1480),
        FragmentContextDisposition::Stale,
    );
}
