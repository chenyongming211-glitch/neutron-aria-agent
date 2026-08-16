use aria_core::ebpf_ops::{
    build_runtime_group_map_entries, classify_managed_inventory_capture,
    classify_runtime_gate_state, collect_standalone_runtime_group_map_entries,
    compile_managed_group_projection, plan_projection_drift,
    replay_standalone_state_to_pinned_maps, validate_general_group_overlap_transition,
    CanonicalNetwork, CapturedProjection, FragmentRuntimeIdentity, GeneralGroupScope,
    GeneralProjectionDisposition, GeneralProjectionExclusionReason, GroupProjectionMode,
    ManagedGroupProjection, ManagedReplayRoute, ProjectionDirection, ProjectionDrift,
    ProjectionEntry, ProjectionMutation, RuntimeGateDisposition, RuntimeNetworkEntry,
    StandaloneReplayRoute,
};
use aria_core::common::{IP_FAMILY_UNSPECIFIED, IP_FAMILY_V4, IP_FAMILY_V6};
use aria_core::state::{
    migrate_legacy_rule_families, FirewallState, GroupInfo, MirrorRuleInfo, QosRuleInfo, RuleInfo,
};
use aria_core::wal::{apply_wal_entry, WalEntry};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn insert_group(state: &mut FirewallState, key: &str, id: u32, cidrs: &[&str]) {
    state.groups.insert(
        key.to_string(),
        GroupInfo {
            id,
            name: key.to_string(),
            cidrs: cidrs.iter().map(|cidr| (*cidr).to_string()).collect(),
        },
    );
    state.next_group_id = state.next_group_id.max(id.saturating_add(1));
}

fn acl_rule(src_group_id: u32, dst_group_id: u32) -> RuleInfo {
    RuleInfo {
        name: Some(format!("acl-{src_group_id}-{dst_group_id}")),
        src_group_id,
        dst_group_id,
        proto: 6,
        action: 1,
        ports: None,
        bitmap_idx: None,
        direction: 0,
        ip_family: IP_FAMILY_V4,
    }
}

fn rule_identity(rule: &RuleInfo) -> (u32, u32, u8, u8, u8) {
    (
        rule.src_group_id,
        rule.dst_group_id,
        rule.proto,
        rule.direction,
        rule.ip_family,
    )
}

#[test]
fn wal_inventory_ipv6_rule_round_trips_family() {
    let stored = WalEntry::AddRule {
        src_id: 10,
        dst_id: 20,
        proto: 6,
        action: 1,
        ports: None,
        direction: 0,
        ip_family: IP_FAMILY_V6,
    };
    let encoded = serde_json::to_string(&stored).expect("WAL entry serializes");
    let decoded: WalEntry = serde_json::from_str(&encoded).expect("WAL entry deserializes");
    let mut replayed = FirewallState::default();

    assert!(apply_wal_entry(&mut replayed, decoded));
    assert_eq!(replayed.rules.len(), 1);
    assert_eq!(rule_identity(&replayed.rules[0]), (10, 20, 6, 0, 6));
}

#[test]
fn local_projection_legacy_ipv4_rule_infers_family() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "ipv4-source", 10, &["10.0.0.0/24"]);
    let mut legacy = acl_rule(10, 0);
    legacy.ip_family = IP_FAMILY_UNSPECIFIED;

    let migrated = migrate_legacy_rule_families(&legacy, &state.groups)
        .expect("one-family legacy selector must infer its family");

    assert_eq!(migrated.len(), 1);
    assert_eq!(rule_identity(&migrated[0]), (10, 0, 6, 0, 4));
}

#[test]
fn local_projection_legacy_any_rule_expands_both_families() {
    let mut legacy = acl_rule(0, 0);
    legacy.ip_family = IP_FAMILY_UNSPECIFIED;

    let migrated = migrate_legacy_rule_families(&legacy, &FirewallState::default().groups)
        .expect("legacy any/any rule must expand into both concrete families");
    let identities = migrated.iter().map(rule_identity).collect::<Vec<_>>();

    assert_eq!(identities, vec![(0, 0, 6, 0, 4), (0, 0, 6, 0, 6)]);
}

#[test]
fn local_projection_legacy_mixed_selector_families_fail_closed_before_replay() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "ipv4-source", 10, &["10.0.0.0/24"]);
    insert_group(&mut state, "ipv6-destination", 20, &["2001:db8::/64"]);
    let mut legacy = acl_rule(10, 20);
    legacy.ip_family = IP_FAMILY_UNSPECIFIED;
    let mut replayed = Vec::new();

    let error = match migrate_legacy_rule_families(&legacy, &state.groups) {
        Ok(rules) => {
            replayed.extend(rules);
            panic!("mixed legacy selector families unexpectedly replayed")
        }
        Err(error) => error,
    };

    assert_eq!(error, "legacy_acl_rule_mixed_family");
    assert!(replayed.is_empty());
}

fn qos_reference(name: &str, group_id: u32) -> QosRuleInfo {
    QosRuleInfo {
        group_name: name.to_string(),
        group_id,
        direction: 0,
        rate_bps: 1_000_000,
        burst_bytes: 64_000,
        priority: 1,
        mode: 0,
    }
}

fn mirror_reference(name: &str, group_id: u32) -> MirrorRuleInfo {
    MirrorRuleInfo {
        src_group_name: name.to_string(),
        src_group_id: group_id,
        dst_group_name: "any".to_string(),
        dst_group_id: 0,
        proto: 0,
        direction: 0,
        target_iface: "mirror0".to_string(),
        target_ifindex: 42,
        is_global: false,
    }
}

fn compile(state: &FirewallState) -> ManagedGroupProjection {
    compile_managed_group_projection(state)
        .unwrap_or_else(|error| panic!("projection should compile: {error}"))
}

fn compile_error(state: &FirewallState) -> String {
    match compile_managed_group_projection(state) {
        Ok(_) => panic!("projection unexpectedly compiled"),
        Err(error) => error,
    }
}

fn entry(cidr: &str, group_id: u32) -> ProjectionEntry {
    ProjectionEntry::parse(cidr, group_id).expect("valid projection entry")
}

fn entries(entries: &[ProjectionEntry]) -> BTreeSet<(String, u32)> {
    entries
        .iter()
        .map(|entry| (entry.network.to_string(), entry.group_id))
        .collect()
}

#[test]
fn managed_projection_replay_routes_cannot_mix_runtime_identity() {
    let compatibility = ManagedReplayRoute::new(GroupProjectionMode::StandaloneCompatibility);
    assert_eq!(
        compatibility.fragment_runtime_identity(),
        FragmentRuntimeIdentity::Managed
    );
    assert_eq!(
        compatibility.projection_mode(),
        GroupProjectionMode::StandaloneCompatibility
    );

    let managed = ManagedReplayRoute::new(GroupProjectionMode::Managed);
    assert_eq!(
        managed.fragment_runtime_identity(),
        FragmentRuntimeIdentity::Managed
    );
    assert_eq!(managed.projection_mode(), GroupProjectionMode::Managed);

    let standalone = StandaloneReplayRoute::new();
    assert_eq!(
        standalone.fragment_runtime_identity(),
        FragmentRuntimeIdentity::Standalone
    );
    assert_eq!(
        standalone.projection_mode(),
        GroupProjectionMode::StandaloneCompatibility
    );

    let _: fn(&str, &str) -> Result<(), String> = replay_standalone_state_to_pinned_maps;
}

fn runtime_entries(entries: &[RuntimeNetworkEntry]) -> BTreeSet<(String, u8, u32)> {
    entries
        .iter()
        .map(|entry| (entry.address.to_string(), entry.prefix_len, entry.group_id))
        .collect()
}

fn has_entry(entries: &[ProjectionEntry], cidr: &str, group_id: u32) -> bool {
    let expected = CanonicalNetwork::parse(cidr).expect("valid expected CIDR");
    entries
        .iter()
        .any(|entry| entry.network == expected && entry.group_id == group_id)
}

#[test]
fn acl_projection_general_overlap_rejects_exact_and_nested_cross_group_membership() {
    let committed = FirewallState::default();
    let mut exact = committed.clone();
    insert_group(&mut exact, "zeta", 2, &["10.0.0.1/24"]);
    insert_group(&mut exact, "alpha", 1, &["10.0.0.254/24"]);

    let exact_error = validate_general_group_overlap_transition(
        &committed,
        &exact,
        GeneralGroupScope::Standalone,
    )
    .expect_err("different groups cannot own one canonical general key");
    assert_eq!(
        exact_error,
        "general_group_overlap:alpha:10.0.0.0/24:zeta:10.0.0.0/24"
    );

    let mut nested = committed.clone();
    insert_group(&mut nested, "broad", 10, &["2001:db8::1/48"]);
    insert_group(&mut nested, "narrow", 20, &["2001:db8:0:1::7/64"]);
    assert_eq!(
        validate_general_group_overlap_transition(
            &committed,
            &nested,
            GeneralGroupScope::Standalone,
        )
        .expect_err("nested IPv6 general membership must be rejected"),
        "general_group_overlap:broad:2001:db8::/48:narrow:2001:db8:0:1::/64"
    );
}

#[test]
fn acl_projection_general_overlap_accepts_same_group_nesting_and_disjoint_groups() {
    let committed = FirewallState::default();
    let mut proposed = committed.clone();
    insert_group(
        &mut proposed,
        "same-owner",
        1,
        &["10.0.0.0/8", "10.1.0.0/16"],
    );
    insert_group(&mut proposed, "disjoint", 2, &["192.0.2.0/24"]);

    validate_general_group_overlap_transition(
        &committed,
        &proposed,
        GeneralGroupScope::Standalone,
    )
    .expect("same membership identity and disjoint groups are representable");
}

#[test]
fn acl_projection_general_overlap_preserves_managed_acl_only_isolation() {
    let committed = FirewallState::default();
    let mut proposed = committed.clone();
    insert_group(&mut proposed, "general", 1, &["10.0.0.0/8"]);
    insert_group(&mut proposed, "acl-only", 2, &["10.1.0.0/16"]);
    proposed.rules.push(acl_rule(2, 0));

    validate_general_group_overlap_transition(
        &committed,
        &proposed,
        GeneralGroupScope::Managed,
    )
    .expect("ACL-only selectors remain isolated from the general identity");

    proposed.qos_rules.push(qos_reference("acl-only", 2));
    assert_eq!(
        validate_general_group_overlap_transition(
            &committed,
            &proposed,
            GeneralGroupScope::Managed,
        )
        .expect_err("QoS use promotes the selector into an ambiguous general identity"),
        "general_group_overlap:acl-only:10.1.0.0/16:general:10.0.0.0/8"
    );
}

#[test]
fn acl_projection_general_overlap_allows_legacy_replay_and_remediation() {
    let mut committed = FirewallState::default();
    insert_group(&mut committed, "broad", 1, &["10.0.0.0/8"]);
    insert_group(&mut committed, "narrow", 2, &["10.1.0.0/16"]);

    let mut unrelated = committed.clone();
    insert_group(&mut unrelated, "disjoint", 3, &["192.0.2.0/24"]);
    validate_general_group_overlap_transition(
        &committed,
        &unrelated,
        GeneralGroupScope::Standalone,
    )
    .expect("an unchanged legacy conflict must not block an unrelated write");

    let mut remediated = committed.clone();
    remediated.groups.remove("narrow");
    validate_general_group_overlap_transition(
        &committed,
        &remediated,
        GeneralGroupScope::Standalone,
    )
    .expect("removing a legacy conflict must remain possible");

    compile_managed_group_projection(&committed)
        .expect("the deterministic compiler must keep replaying legacy overlap");
}

#[test]
fn acl_projection_uses_directional_rule_references_and_omits_group_zero() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "src", 1, &["10.0.0.1/24"]);
    insert_group(&mut state, "dst", 2, &["10.0.0.2/24"]);
    insert_group(&mut state, "unused", 3, &["192.0.2.0/24"]);
    state
        .rules
        .extend([acl_rule(1, 2), acl_rule(0, 2), acl_rule(1, 0)]);

    let compiled = compile(&state);

    assert_eq!(
        entries(&compiled.acl_src),
        entries(&[entry("10.0.0.0/24", 1)])
    );
    assert_eq!(
        entries(&compiled.acl_dst),
        entries(&[entry("10.0.0.0/24", 2)])
    );
    assert!(!compiled
        .acl_src
        .iter()
        .chain(&compiled.acl_dst)
        .any(|projected| projected.group_id == 0 || projected.group_id == 3));
}

#[test]
fn acl_projection_is_reference_driven_instead_of_name_driven() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "plain-local-name", 7, &["198.51.100.3/24"]);
    state.rules.push(acl_rule(7, 0));

    let compiled = compile(&state);

    assert!(has_entry(&compiled.acl_src, "198.51.100.0/24", 7));
    assert!(compiled.acl_dst.is_empty());
}

#[test]
fn acl_projection_rejects_missing_duplicate_and_invalid_group_state() {
    let mut missing = FirewallState::default();
    missing.rules.push(acl_rule(41, 0));
    let error = compile_error(&missing);
    assert!(
        error.to_ascii_lowercase().contains("missing") && error.contains("41"),
        "{error}"
    );

    let mut duplicate = FirewallState::default();
    insert_group(&mut duplicate, "duplicate-a", 7, &["10.0.0.0/24"]);
    insert_group(&mut duplicate, "duplicate-b", 7, &["10.1.0.0/24"]);
    duplicate.rules.push(acl_rule(7, 0));
    let error = compile_error(&duplicate);
    assert!(
        error.to_ascii_lowercase().contains("duplicate") && error.contains('7'),
        "{error}"
    );

    let mut invalid = FirewallState::default();
    insert_group(&mut invalid, "invalid", 9, &["not-a-cidr"]);
    let error = compile_error(&invalid);
    assert!(
        error.to_ascii_lowercase().contains("invalid") && error.contains("not-a-cidr"),
        "{error}"
    );
}

#[test]
fn acl_projection_canonicalizes_ipv4_and_ipv6_host_bits_before_deduplication() {
    let mut state = FirewallState::default();
    insert_group(
        &mut state,
        "selector",
        1,
        &[
            "10.0.0.1/24",
            "10.0.0.254/24",
            "2001:db8::1/64",
            "2001:db8::ffff/64",
        ],
    );
    state.rules.push(acl_rule(1, 0));

    let compiled = compile(&state);

    assert_eq!(compiled.acl_src.len(), 2);
    assert!(has_entry(&compiled.acl_src, "10.0.0.0/24", 1));
    assert!(has_entry(&compiled.acl_src, "2001:db8::/64", 1));
}

#[test]
fn acl_projection_allows_same_owner_nesting_and_rejects_cross_owner_overlap() {
    let mut same_owner = FirewallState::default();
    insert_group(
        &mut same_owner,
        "selector",
        1,
        &[
            "10.0.0.0/24",
            "10.0.0.10/32",
            "2001:db8::/64",
            "2001:db8::10/128",
        ],
    );
    same_owner.rules.push(acl_rule(1, 0));
    assert_eq!(compile(&same_owner).acl_src.len(), 4);

    let mut exact = FirewallState::default();
    insert_group(&mut exact, "first", 1, &["10.0.0.1/24"]);
    insert_group(&mut exact, "second", 2, &["10.0.0.2/24"]);
    exact.rules.extend([acl_rule(1, 0), acl_rule(2, 0)]);
    let error = compile_error(&exact);
    assert!(
        error.to_ascii_lowercase().contains("overlap")
            || error.to_ascii_lowercase().contains("canonical"),
        "{error}"
    );

    let mut nested = FirewallState::default();
    insert_group(&mut nested, "broad", 3, &["2001:db8::/64"]);
    insert_group(&mut nested, "narrow", 4, &["2001:db8::10/128"]);
    nested.rules.extend([acl_rule(3, 0), acl_rule(4, 0)]);
    let error = compile_error(&nested);
    assert!(error.to_ascii_lowercase().contains("overlap"), "{error}");
}

#[test]
fn acl_projection_general_precedence_handles_exact_and_specificity_cases() {
    let mut exact = FirewallState::default();
    insert_group(&mut exact, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut exact, "local", 20, &["10.0.0.0/24"]);
    exact.rules.push(acl_rule(10, 0));
    let compiled = compile(&exact);
    assert!(has_entry(&compiled.acl_src, "10.0.0.0/24", 10));
    assert!(has_entry(&compiled.general, "10.0.0.0/24", 20));
    assert!(!has_entry(&compiled.general, "10.0.0.0/24", 10));

    let mut broader_general = FirewallState::default();
    insert_group(&mut broader_general, "acl", 10, &["10.0.0.10/32"]);
    insert_group(&mut broader_general, "local", 20, &["10.0.0.0/24"]);
    broader_general.rules.push(acl_rule(10, 0));
    let compiled = compile(&broader_general);
    assert!(!has_entry(&compiled.general, "10.0.0.10/32", 10));
    assert!(has_entry(&compiled.acl_src, "10.0.0.10/32", 10));

    let mut more_specific_general = FirewallState::default();
    insert_group(&mut more_specific_general, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut more_specific_general, "local", 20, &["10.0.0.10/32"]);
    more_specific_general.rules.push(acl_rule(10, 0));
    let compiled = compile(&more_specific_general);
    assert!(has_entry(&compiled.general, "10.0.0.0/24", 10));
    assert!(has_entry(&compiled.general, "10.0.0.10/32", 20));
}

#[test]
fn acl_projection_retains_non_conflicting_acl_only_general_observability() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut state, "local", 20, &["192.0.2.0/24"]);
    state.rules.push(acl_rule(10, 0));

    let compiled = compile(&state);

    assert!(has_entry(&compiled.general, "10.0.0.0/24", 10));
    assert!(has_entry(&compiled.general, "192.0.2.0/24", 20));
}

#[test]
fn acl_projection_qos_and_mirror_refs_make_acl_groups_general_domain() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "acl-qos", 30, &["10.1.0.0/24"]);
    insert_group(&mut state, "local-qos", 20, &["10.1.0.0/24"]);
    insert_group(&mut state, "acl-mirror", 40, &["10.2.0.0/24"]);
    insert_group(&mut state, "local-mirror", 35, &["10.2.0.0/24"]);
    state.rules.push(acl_rule(30, 40));
    state.qos_rules.push(qos_reference("acl-qos", 30));
    state.mirror_rules.push(mirror_reference("acl-mirror", 40));

    let compiled = compile(&state);

    assert!(has_entry(&compiled.general, "10.1.0.0/24", 30));
    assert!(has_entry(&compiled.general, "10.2.0.0/24", 40));
    assert!(has_entry(&compiled.acl_src, "10.1.0.0/24", 30));
    assert!(has_entry(&compiled.acl_dst, "10.2.0.0/24", 40));
}

#[test]
fn acl_projection_highest_id_exact_winner_is_insertion_order_independent() {
    fn alias_state(order: &[(&str, u32)]) -> FirewallState {
        let mut state = FirewallState::default();
        for (name, id) in order {
            insert_group(&mut state, name, *id, &["198.51.100.7/24"]);
        }
        state
    }

    let forward = compile(&alias_state(&[("low", 3), ("high", 9), ("middle", 5)]));
    let reverse = compile(&alias_state(&[("middle", 5), ("high", 9), ("low", 3)]));

    assert_eq!(forward, reverse);
    assert_eq!(
        entries(&forward.general),
        entries(&[entry("198.51.100.0/24", 9)])
    );
}

#[test]
fn acl_projection_canonical_network_checked_constructor_preserves_invariants() {
    assert_eq!(
        CanonicalNetwork::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)), 24).unwrap(),
        CanonicalNetwork::parse("10.0.0.0/24").unwrap()
    );
    assert_eq!(
        CanonicalNetwork::from_ip(IpAddr::V6("2001:db8::ffff".parse().unwrap()), 64).unwrap(),
        CanonicalNetwork::parse("2001:db8::/64").unwrap()
    );
    assert_eq!(
        CanonicalNetwork::parse("203.0.113.7/0")
            .unwrap()
            .to_string(),
        "0.0.0.0/0"
    );
    assert!(CanonicalNetwork::from_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33).is_err());
    assert!(CanonicalNetwork::from_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 129).is_err());
}

#[test]
fn acl_projection_reports_cross_domain_cover_independently_of_group_id() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "higher-id-acl", 50, &["10.0.0.7/24"]);
    insert_group(&mut state, "lower-id-local", 20, &["10.0.0.9/24"]);
    state.rules.push(acl_rule(50, 0));

    let compiled = compile(&state);
    let acl_candidate = compiled
        .general_candidates
        .iter()
        .find(|candidate| candidate.stable_group_identity == "higher-id-acl")
        .expect("ACL candidate metadata exists");

    assert!(has_entry(&compiled.general, "10.0.0.0/24", 20));
    assert!(matches!(
        &acl_candidate.disposition,
        GeneralProjectionDisposition::Excluded(
            GeneralProjectionExclusionReason::CoveredByGeneralDomain { covering }
        ) if covering == &entry("10.0.0.0/24", 20)
    ));
}

#[test]
fn acl_projection_reports_exact_winner_and_most_specific_cover_deterministically() {
    fn state_with_order(order: &[(&str, u32, &str)]) -> FirewallState {
        let mut state = FirewallState::default();
        for (name, id, cidr) in order {
            insert_group(&mut state, name, *id, &[*cidr]);
        }
        state.rules.push(acl_rule(30, 0));
        state
    }

    let forward = compile(&state_with_order(&[
        ("acl", 30, "10.0.1.9/32"),
        ("broad", 10, "10.0.0.0/16"),
        ("specific", 20, "10.0.1.0/24"),
        ("exact-low", 3, "192.0.2.1/24"),
        ("exact-high", 9, "192.0.2.200/24"),
    ]));
    let reverse = compile(&state_with_order(&[
        ("exact-high", 9, "192.0.2.200/24"),
        ("exact-low", 3, "192.0.2.1/24"),
        ("specific", 20, "10.0.1.0/24"),
        ("broad", 10, "10.0.0.0/16"),
        ("acl", 30, "10.0.1.9/32"),
    ]));
    assert_eq!(forward, reverse);

    let acl_candidate = forward
        .general_candidates
        .iter()
        .find(|candidate| candidate.stable_group_identity == "acl")
        .expect("ACL candidate metadata exists");
    assert!(matches!(
        &acl_candidate.disposition,
        GeneralProjectionDisposition::Excluded(
            GeneralProjectionExclusionReason::CoveredByGeneralDomain { covering }
        ) if covering == &entry("10.0.1.0/24", 20)
    ));

    let exact_low = forward
        .general_candidates
        .iter()
        .find(|candidate| candidate.stable_group_identity == "exact-low")
        .expect("low exact candidate metadata exists");
    assert!(matches!(
        &exact_low.disposition,
        GeneralProjectionDisposition::Excluded(
            GeneralProjectionExclusionReason::ExactKeyLost { winner }
        ) if winner == &entry("192.0.2.0/24", 9)
    ));
    let exact_high = forward
        .general_candidates
        .iter()
        .find(|candidate| candidate.stable_group_identity == "exact-high")
        .expect("high exact candidate metadata exists");
    assert_eq!(
        exact_high.disposition,
        GeneralProjectionDisposition::Included
    );
}

#[test]
fn managed_projection_replay_standalone_mode_preserves_all_group_compatibility() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "zero", 0, &["203.0.113.9/24"]);
    insert_group(&mut state, "acl", 10, &["10.0.0.7/24"]);
    insert_group(&mut state, "unused", 20, &["2001:db8::7/64"]);
    state.rules.push(acl_rule(10, 0));

    let projected =
        build_runtime_group_map_entries(&state, GroupProjectionMode::StandaloneCompatibility)
            .expect("standalone compatibility projection compiles");
    let expected = BTreeSet::from([
        ("10.0.0.7".to_string(), 24, 10),
        ("2001:db8::7".to_string(), 64, 20),
        ("203.0.113.9".to_string(), 24, 0),
    ]);

    assert_eq!(runtime_entries(&projected.general_src), expected);
    assert_eq!(runtime_entries(&projected.general_dst), expected);
    assert_eq!(runtime_entries(&projected.acl_src), expected);
    assert_eq!(runtime_entries(&projected.acl_dst), expected);
}

#[test]
fn managed_projection_replay_standalone_parse_errors_preserve_valid_entries() {
    let mut state = FirewallState::default();
    insert_group(
        &mut state,
        "mixed",
        10,
        &["10.0.0.7/24", "not-a-cidr", "2001:db8::7/64"],
    );

    let (projected, errors) = collect_standalone_runtime_group_map_entries(&state);
    let expected = BTreeSet::from([
        ("10.0.0.7".to_string(), 24, 10),
        ("2001:db8::7".to_string(), 64, 10),
    ]);

    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("group 'mixed' cidr 'not-a-cidr'"));
    assert_eq!(runtime_entries(&projected.general_src), expected);
    assert_eq!(runtime_entries(&projected.general_dst), expected);
    assert_eq!(runtime_entries(&projected.acl_src), expected);
    assert_eq!(runtime_entries(&projected.acl_dst), expected);
    assert!(
        build_runtime_group_map_entries(&state, GroupProjectionMode::StandaloneCompatibility,)
            .is_err()
    );
}

#[test]
fn managed_projection_replay_mode_uses_conflict_aware_directional_entries() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "acl-src", 10, &["10.0.0.7/32"]);
    insert_group(&mut state, "acl-dst", 11, &["2001:db8::7/64"]);
    insert_group(&mut state, "local", 20, &["10.0.0.0/24"]);
    insert_group(&mut state, "unused", 30, &["192.0.2.9/24"]);
    state.rules.push(acl_rule(10, 11));

    let projected = build_runtime_group_map_entries(&state, GroupProjectionMode::Managed)
        .expect("managed runtime projection compiles");

    assert_eq!(
        runtime_entries(&projected.acl_src),
        BTreeSet::from([("10.0.0.7".to_string(), 32, 10)])
    );
    assert_eq!(
        runtime_entries(&projected.acl_dst),
        BTreeSet::from([("2001:db8::".to_string(), 64, 11)])
    );
    assert_eq!(
        runtime_entries(&projected.general_src),
        BTreeSet::from([
            ("10.0.0.0".to_string(), 24, 20),
            ("192.0.2.0".to_string(), 24, 30),
            ("2001:db8::".to_string(), 64, 11),
        ])
    );
    assert_eq!(
        runtime_entries(&projected.general_dst),
        runtime_entries(&projected.general_src)
    );
    assert!(!runtime_entries(&projected.general_src).contains(&("10.0.0.7".to_string(), 32, 10,)));
}

#[test]
fn managed_projection_inventory_expected_sets_match_the_managed_compiler() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "src", 1, &["10.0.0.9/24"]);
    insert_group(&mut state, "dst", 2, &["2001:db8::9/64"]);
    insert_group(&mut state, "local", 3, &["192.0.2.9/24"]);
    state.rules.push(acl_rule(1, 2));

    let compiled = compile(&state);
    let expected = build_runtime_group_map_entries(&state, GroupProjectionMode::Managed)
        .expect("managed inventory projection compiles");

    let general: BTreeSet<(String, u8, u32)> = compiled
        .general
        .iter()
        .map(|entry| {
            (
                entry.network.network_address().to_string(),
                entry.network.prefix_len(),
                entry.group_id,
            )
        })
        .collect();
    let acl_src: BTreeSet<(String, u8, u32)> = compiled
        .acl_src
        .iter()
        .map(|entry| {
            (
                entry.network.network_address().to_string(),
                entry.network.prefix_len(),
                entry.group_id,
            )
        })
        .collect();
    let acl_dst: BTreeSet<(String, u8, u32)> = compiled
        .acl_dst
        .iter()
        .map(|entry| {
            (
                entry.network.network_address().to_string(),
                entry.network.prefix_len(),
                entry.group_id,
            )
        })
        .collect();

    assert_eq!(runtime_entries(&expected.general_src), general);
    assert_eq!(runtime_entries(&expected.general_dst), general);
    assert_eq!(runtime_entries(&expected.acl_src), acl_src);
    assert_eq!(runtime_entries(&expected.acl_dst), acl_dst);
}

#[test]
fn managed_projection_inventory_gate_state_keeps_quiesced_restart_unverified() {
    assert_eq!(
        classify_runtime_gate_state(GroupProjectionMode::Managed, 1, 1, 1, 1,),
        Ok(RuntimeGateDisposition::Desired)
    );
    assert_eq!(
        classify_runtime_gate_state(GroupProjectionMode::Managed, 0, 0, 1, 1,),
        Ok(RuntimeGateDisposition::ManagedQuiesced)
    );
    assert_eq!(
        classify_runtime_gate_state(GroupProjectionMode::Managed, 0, 0, 0, 1,),
        Ok(RuntimeGateDisposition::ManagedQuiesced)
    );
    assert!(
        classify_runtime_gate_state(GroupProjectionMode::StandaloneCompatibility, 0, 0, 1, 1,)
            .is_err()
    );
    assert!(classify_runtime_gate_state(GroupProjectionMode::Managed, 0, 1, 1, 1,).is_err());
}

#[test]
fn managed_projection_inventory_classifies_legacy_then_converges_to_clean() {
    let mut exact_state = FirewallState::default();
    insert_group(&mut exact_state, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut exact_state, "local", 20, &["10.0.0.0/24"]);
    exact_state.rules.push(acl_rule(10, 0));
    let exact = compile(&exact_state);

    let mut replaced = CapturedProjection::from(&exact);
    replaced.acl_src = vec![entry("10.0.0.0/24", 20)];
    assert!(matches!(
        classify_managed_inventory_capture(&exact_state, &replaced, Ok(())),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut missing = CapturedProjection::from(&exact);
    missing.acl_src.clear();
    assert!(matches!(
        classify_managed_inventory_capture(&exact_state, &missing, Ok(())),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut destination_state = FirewallState::default();
    insert_group(
        &mut destination_state,
        "acl-destination",
        11,
        &["2001:db8::/64"],
    );
    insert_group(
        &mut destination_state,
        "local-destination-alias",
        21,
        &["2001:db8::/64"],
    );
    destination_state.rules.push(acl_rule(0, 11));
    let destination = compile(&destination_state);
    let mut destination_missing = CapturedProjection::from(&destination);
    destination_missing.acl_dst.clear();
    assert!(matches!(
        classify_managed_inventory_capture(&destination_state, &destination_missing, Ok(())),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut specific_state = FirewallState::default();
    insert_group(&mut specific_state, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut specific_state, "local", 20, &["10.0.0.7/32"]);
    specific_state.rules.push(acl_rule(10, 0));
    let specific = compile(&specific_state);
    let mut more_specific = CapturedProjection::from(&specific);
    more_specific.acl_src.push(entry("10.0.0.7/32", 20));
    assert!(matches!(
        classify_managed_inventory_capture(&specific_state, &more_specific, Ok(())),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut general_alias = CapturedProjection::from(&exact);
    general_alias.general_src = vec![entry("10.0.0.0/24", 10)];
    assert!(matches!(
        classify_managed_inventory_capture(&exact_state, &general_alias, Ok(())),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut general_missing = CapturedProjection::from(&exact);
    general_missing.general_dst.clear();
    assert!(matches!(
        classify_managed_inventory_capture(&exact_state, &general_missing, Ok(())),
        ProjectionDrift::RepairRequired(_)
    ));

    assert!(matches!(
        classify_managed_inventory_capture(&exact_state, &CapturedProjection::from(&exact), Ok(())),
        ProjectionDrift::Clean
    ));
}

#[test]
fn managed_projection_inventory_keeps_unknown_and_non_projection_drift_fatal() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut state, "local", 20, &["10.0.0.0/24"]);
    state.rules.push(acl_rule(10, 0));
    let compiled = compile(&state);

    let mut unknown_acl_destination_key = CapturedProjection::from(&compiled);
    unknown_acl_destination_key
        .acl_dst
        .push(entry("203.0.113.0/24", 10));
    assert!(matches!(
        classify_managed_inventory_capture(&state, &unknown_acl_destination_key, Ok(())),
        ProjectionDrift::Fatal(_)
    ));

    let mut unknown_general_value = CapturedProjection::from(&compiled);
    unknown_general_value.general_dst = vec![entry("10.0.0.0/24", 999)];
    assert!(matches!(
        classify_managed_inventory_capture(&state, &unknown_general_value, Ok(())),
        ProjectionDrift::Fatal(_)
    ));

    let mut repairable = CapturedProjection::from(&compiled);
    repairable.acl_src = vec![entry("10.0.0.0/24", 20)];
    assert!(matches!(
        classify_managed_inventory_capture(&state, &repairable, Ok(())),
        ProjectionDrift::RepairRequired(_)
    ));
    for strict_error in [
        "POLICY_TABLE drift",
        "TAP_CONFIG_MAP drift",
        "TC link drift",
    ] {
        match classify_managed_inventory_capture(
            &state,
            &CapturedProjection::from(&compiled),
            Err(strict_error.to_string()),
        ) {
            ProjectionDrift::Fatal(message) => {
                assert!(message.contains(strict_error), "{message}")
            }
            other => panic!("non-projection drift must dominate clean, got {other:?}"),
        }
        match classify_managed_inventory_capture(&state, &repairable, Err(strict_error.to_string()))
        {
            ProjectionDrift::Fatal(message) => {
                assert!(message.contains(strict_error), "{message}")
            }
            other => panic!("non-projection drift must dominate repair, got {other:?}"),
        }
    }
}

#[test]
fn acl_projection_drift_recognizes_exact_more_specific_missing_and_general_legacy() {
    let mut exact_state = FirewallState::default();
    insert_group(&mut exact_state, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut exact_state, "local", 20, &["10.0.0.0/24"]);
    exact_state.rules.push(acl_rule(10, 0));
    let exact = compile(&exact_state);

    let mut replaced = CapturedProjection::from(&exact);
    replaced.acl_src = vec![entry("10.0.0.0/24", 20)];
    assert!(matches!(
        plan_projection_drift(&replaced, &exact, &exact),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut missing = CapturedProjection::from(&exact);
    missing.acl_src.clear();
    assert!(matches!(
        plan_projection_drift(&missing, &exact, &exact),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut specific_state = FirewallState::default();
    insert_group(&mut specific_state, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut specific_state, "local", 20, &["10.0.0.10/32"]);
    specific_state.rules.push(acl_rule(10, 0));
    let specific = compile(&specific_state);
    let mut more_specific = CapturedProjection::from(&specific);
    more_specific.acl_src.push(entry("10.0.0.10/32", 20));
    assert!(matches!(
        plan_projection_drift(&more_specific, &specific, &specific),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut excluded_state = FirewallState::default();
    insert_group(&mut excluded_state, "acl", 10, &["2001:db8::10/128"]);
    insert_group(&mut excluded_state, "local", 20, &["2001:db8::/64"]);
    excluded_state.rules.push(acl_rule(10, 0));
    let excluded = compile(&excluded_state);
    let mut legacy_general = CapturedProjection::from(&excluded);
    legacy_general
        .general_src
        .push(entry("2001:db8::10/128", 10));
    legacy_general
        .general_dst
        .push(entry("2001:db8::10/128", 10));
    match plan_projection_drift(&legacy_general, &excluded, &excluded) {
        ProjectionDrift::RepairRequired(plan) => {
            let deleted_directions: BTreeSet<ProjectionDirection> = plan
                .general_mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    ProjectionMutation::Deleted {
                        direction,
                        entry: removed,
                    } if removed == &entry("2001:db8::10/128", 10) => Some(*direction),
                    _ => None,
                })
                .collect();
            assert_eq!(
                deleted_directions,
                BTreeSet::from([ProjectionDirection::Src, ProjectionDirection::Dst])
            );
        }
        other => panic!("known general legacy entry must be repairable, got {other:?}"),
    }

    let mut exact_general_alias = CapturedProjection::from(&exact);
    exact_general_alias.general_src = vec![entry("10.0.0.0/24", 10)];
    exact_general_alias.general_dst = vec![entry("10.0.0.0/24", 10)];
    match plan_projection_drift(&exact_general_alias, &exact, &exact) {
        ProjectionDrift::RepairRequired(plan) => {
            let replaced_directions: BTreeSet<ProjectionDirection> = plan
                .general_mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    ProjectionMutation::Replaced {
                        direction,
                        network,
                        old_group_id: 10,
                        new_group_id: 20,
                    } if network == &CanonicalNetwork::parse("10.0.0.0/24").unwrap() => {
                        Some(*direction)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                replaced_directions,
                BTreeSet::from([ProjectionDirection::Src, ProjectionDirection::Dst])
            );
        }
        other => panic!("known exact general alias must be repairable, got {other:?}"),
    }

    let mut exact_general_missing = CapturedProjection::from(&exact);
    exact_general_missing.general_src.clear();
    exact_general_missing.general_dst.clear();
    match plan_projection_drift(&exact_general_missing, &exact, &exact) {
        ProjectionDrift::RepairRequired(plan) => {
            let added_directions: BTreeSet<ProjectionDirection> = plan
                .general_mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    ProjectionMutation::Added {
                        direction,
                        entry: added,
                    } if added == &entry("10.0.0.0/24", 20) => Some(*direction),
                    _ => None,
                })
                .collect();
            assert_eq!(
                added_directions,
                BTreeSet::from([ProjectionDirection::Src, ProjectionDirection::Dst])
            );
        }
        other => panic!("known exact general deletion must be repairable, got {other:?}"),
    }
}

#[test]
fn acl_projection_drift_distinguishes_clean_and_fatal_runtime() {
    let mut state = FirewallState::default();
    insert_group(&mut state, "acl", 10, &["10.0.0.0/24"]);
    state.rules.push(acl_rule(10, 0));
    let committed = compile(&state);

    let clean = CapturedProjection::from(&committed);
    assert!(matches!(
        plan_projection_drift(&clean, &committed, &committed),
        ProjectionDrift::Clean
    ));

    let mut unknown = CapturedProjection::from(&committed);
    unknown.acl_src.push(entry("203.0.113.0/24", 999));
    match plan_projection_drift(&unknown, &committed, &committed) {
        ProjectionDrift::Fatal(message) => assert!(
            message.contains("999") || message.to_ascii_lowercase().contains("unknown"),
            "{message}"
        ),
        other => panic!("unknown runtime key/value must be fatal, got {other:?}"),
    }

    let mut unknown_value_for_owned_key = CapturedProjection::from(&committed);
    unknown_value_for_owned_key.acl_src = vec![entry("10.0.0.0/24", 999)];
    assert!(matches!(
        plan_projection_drift(&unknown_value_for_owned_key, &committed, &committed),
        ProjectionDrift::RepairRequired(_)
    ));

    let mut unexplained_missing = CapturedProjection::from(&committed);
    unexplained_missing.acl_src.clear();
    assert!(matches!(
        plan_projection_drift(&unexplained_missing, &committed, &committed),
        ProjectionDrift::Fatal(_)
    ));
}

#[test]
fn acl_projection_drift_classifies_committed_then_repairs_directly_to_proposed() {
    let mut committed_state = FirewallState::default();
    insert_group(&mut committed_state, "acl", 10, &["10.0.0.0/24"]);
    insert_group(&mut committed_state, "local", 20, &["10.0.0.0/24"]);
    committed_state.rules.push(acl_rule(10, 0));
    let committed = compile(&committed_state);

    let mut captured = CapturedProjection::from(&committed);
    captured.acl_src = vec![entry("10.0.0.0/24", 20)];

    let mut proposed_state = committed_state;
    proposed_state.groups.remove("local");
    proposed_state
        .groups
        .get_mut("acl")
        .expect("ACL group exists")
        .cidrs = vec!["10.0.1.0/24".to_string()];
    let proposed = compile(&proposed_state);
    assert!(has_entry(&proposed.acl_src, "10.0.1.0/24", 10));

    match plan_projection_drift(&captured, &committed, &proposed) {
        ProjectionDrift::RepairRequired(plan) => {
            let deleted_directions: BTreeSet<ProjectionDirection> = plan
                .general_mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    ProjectionMutation::Deleted {
                        direction,
                        entry: removed,
                    } if removed == &entry("10.0.0.0/24", 20) => Some(*direction),
                    _ => None,
                })
                .collect();
            let added_directions: BTreeSet<ProjectionDirection> = plan
                .general_mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    ProjectionMutation::Added {
                        direction,
                        entry: added,
                    } if added == &entry("10.0.1.0/24", 10) => Some(*direction),
                    _ => None,
                })
                .collect();
            let both = BTreeSet::from([ProjectionDirection::Src, ProjectionDirection::Dst]);
            assert_eq!(deleted_directions, both);
            assert_eq!(added_directions, both);
        }
        other => panic!("legacy drift plus proposed change must repair, got {other:?}"),
    }
}
