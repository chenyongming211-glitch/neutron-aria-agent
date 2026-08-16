use aria_ebpf_abi::*;

#[test]
fn acl_family_layout_and_cache_contract() {
    assert_eq!(IP_FAMILY_UNSPECIFIED, 0);
    assert_eq!(IP_FAMILY_V4, 4);
    assert_eq!(IP_FAMILY_V6, 6);
    assert_eq!(core::mem::size_of::<PolicyKey>(), 16);
    assert_eq!(core::mem::size_of::<CtValue>(), 40);
    assert_eq!(core::mem::size_of::<DropKey>(), 16);
    assert!(policy_family_is_valid(IP_FAMILY_V4));
    assert!(policy_family_is_valid(IP_FAMILY_V6));
    assert!(!policy_family_is_valid(IP_FAMILY_UNSPECIFIED));
    assert!(drop_family_is_valid(IP_FAMILY_UNSPECIFIED));
    assert!(!ct_acl_family_is_current(0, IP_FAMILY_V6));
    assert!(!ct_acl_family_is_current(IP_FAMILY_V4, IP_FAMILY_V6));
    assert!(ct_acl_family_is_current(IP_FAMILY_V6, IP_FAMILY_V6));
}
