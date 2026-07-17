use super::network::CanonicalNetwork;
use crate::state::FirewallState;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionEntry {
    pub network: CanonicalNetwork,
    pub group_id: u32,
}

impl ProjectionEntry {
    pub fn parse(cidr: &str, group_id: u32) -> Result<Self, String> {
        Ok(Self {
            network: CanonicalNetwork::parse(cidr)?,
            group_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedGroupProjection {
    pub acl_src: Vec<ProjectionEntry>,
    pub acl_dst: Vec<ProjectionEntry>,
    pub general: Vec<ProjectionEntry>,
    pub legacy_candidates: Vec<ProjectionEntry>,
    pub general_candidates: Vec<GeneralProjectionCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GeneralProjectionCandidate {
    pub entry: ProjectionEntry,
    pub stable_group_identity: String,
    pub disposition: GeneralProjectionDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GeneralProjectionDisposition {
    Included,
    Excluded(GeneralProjectionExclusionReason),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GeneralProjectionExclusionReason {
    CoveredByGeneralDomain { covering: ProjectionEntry },
    ExactKeyLost { winner: ProjectionEntry },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedProjection {
    pub general_src: Vec<ProjectionEntry>,
    pub general_dst: Vec<ProjectionEntry>,
    pub acl_src: Vec<ProjectionEntry>,
    pub acl_dst: Vec<ProjectionEntry>,
}

impl From<&ManagedGroupProjection> for CapturedProjection {
    fn from(projection: &ManagedGroupProjection) -> Self {
        Self {
            general_src: projection.general.clone(),
            general_dst: projection.general.clone(),
            acl_src: projection.acl_src.clone(),
            acl_dst: projection.acl_dst.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProjectionDirection {
    Src,
    Dst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionMutation {
    Added {
        direction: ProjectionDirection,
        entry: ProjectionEntry,
    },
    Deleted {
        direction: ProjectionDirection,
        entry: ProjectionEntry,
    },
    Replaced {
        direction: ProjectionDirection,
        network: CanonicalNetwork,
        old_group_id: u32,
        new_group_id: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRepairPlan {
    pub general_mutations: Vec<ProjectionMutation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionDrift {
    Clean,
    RepairRequired(ProjectionRepairPlan),
    Fatal(String),
}

#[derive(Debug, Clone)]
struct PersistedGroup {
    stable_name: String,
    id: u32,
    networks: Vec<CanonicalNetwork>,
}

pub fn compile_managed_group_projection(
    state: &FirewallState,
) -> Result<ManagedGroupProjection, String> {
    let groups = collect_persisted_groups(state)?;
    let (acl_src_ids, acl_dst_ids, explicit_general_ids) = collect_references(state, &groups)?;

    let acl_src = compile_acl_direction("source", &acl_src_ids, &groups)?;
    let acl_dst = compile_acl_direction("destination", &acl_dst_ids, &groups)?;

    let acl_ids: BTreeSet<u32> = acl_src_ids.union(&acl_dst_ids).copied().collect();
    let acl_only_ids: BTreeSet<u32> = acl_ids.difference(&explicit_general_ids).copied().collect();
    let general_domain_ids: BTreeSet<u32> = groups
        .keys()
        .copied()
        .filter(|id| !acl_only_ids.contains(id))
        .collect();

    let general_domain_entries = entries_for_ids(&general_domain_ids, &groups);
    let general_domain_winners = select_highest_exact_winners(general_domain_entries);
    let mut retained_general = general_domain_winners.clone();
    for group_id in &acl_only_ids {
        let group = groups
            .get(group_id)
            .expect("ACL references were validated before projection");
        for network in &group.networks {
            if most_specific_covering_entry(network, &general_domain_winners).is_none() {
                retained_general.push(ProjectionEntry {
                    network: *network,
                    group_id: *group_id,
                });
            }
        }
    }

    let general = select_highest_exact_winners(retained_general);
    let general_candidates =
        describe_general_candidates(&groups, &acl_only_ids, &general_domain_winners, &general);
    let legacy_candidates = general_candidates
        .iter()
        .map(|candidate| candidate.entry)
        .collect();

    Ok(ManagedGroupProjection {
        acl_src,
        acl_dst,
        general,
        legacy_candidates,
        general_candidates,
    })
}

pub fn plan_projection_drift(
    captured: &CapturedProjection,
    committed: &ManagedGroupProjection,
    proposed: &ManagedGroupProjection,
) -> ProjectionDrift {
    let candidate_index = legacy_candidate_index(committed);
    let captured_maps = [
        ("general source", &captured.general_src, &committed.general),
        (
            "general destination",
            &captured.general_dst,
            &committed.general,
        ),
        ("ACL source", &captured.acl_src, &committed.acl_src),
        ("ACL destination", &captured.acl_dst, &committed.acl_dst),
    ];

    let mut repair_required = false;
    for (label, actual_entries, expected_entries) in captured_maps {
        let actual = match normalize_entries(actual_entries, label) {
            Ok(entries) => entries,
            Err(error) => return ProjectionDrift::Fatal(error),
        };
        let expected = match normalize_entries(expected_entries, label) {
            Ok(entries) => entries,
            Err(error) => return ProjectionDrift::Fatal(error),
        };
        match classify_map_drift(label, &actual, &expected, &candidate_index) {
            Ok(is_drifted) => repair_required |= is_drifted,
            Err(error) => return ProjectionDrift::Fatal(error),
        }
    }

    if !repair_required {
        return ProjectionDrift::Clean;
    }

    let proposed_general = match normalize_entries(&proposed.general, "proposed general") {
        Ok(entries) => entries,
        Err(error) => return ProjectionDrift::Fatal(error),
    };
    let captured_general_src = match normalize_entries(&captured.general_src, "general source") {
        Ok(entries) => entries,
        Err(error) => return ProjectionDrift::Fatal(error),
    };
    let captured_general_dst = match normalize_entries(&captured.general_dst, "general destination")
    {
        Ok(entries) => entries,
        Err(error) => return ProjectionDrift::Fatal(error),
    };

    let general_mutations = build_general_mutations(
        &captured_general_src,
        &captured_general_dst,
        &proposed_general,
    );
    ProjectionDrift::RepairRequired(ProjectionRepairPlan { general_mutations })
}

fn collect_persisted_groups(
    state: &FirewallState,
) -> Result<BTreeMap<u32, PersistedGroup>, String> {
    let mut persisted: Vec<_> = state.groups.iter().collect();
    persisted.sort_by(|(left_key, _), (right_key, _)| left_key.cmp(right_key));

    let mut groups = BTreeMap::new();
    for (map_key, group) in persisted {
        if group.id == 0 {
            continue;
        }
        if let Some(existing) = groups.get(&group.id) {
            return Err(format!(
                "duplicate persisted group ID {} for '{}' and '{}'",
                group.id, existing.stable_name, map_key
            ));
        }

        let mut networks = BTreeSet::new();
        for cidr in &group.cidrs {
            let network = CanonicalNetwork::parse(cidr).map_err(|error| {
                format!(
                    "invalid CIDR '{}' in persisted group '{}' (ID {}): {}",
                    cidr, map_key, group.id, error
                )
            })?;
            networks.insert(network);
        }
        groups.insert(
            group.id,
            PersistedGroup {
                stable_name: (*map_key).clone(),
                id: group.id,
                networks: networks.into_iter().collect(),
            },
        );
    }
    Ok(groups)
}

fn collect_references(
    state: &FirewallState,
    groups: &BTreeMap<u32, PersistedGroup>,
) -> Result<(BTreeSet<u32>, BTreeSet<u32>, BTreeSet<u32>), String> {
    let mut acl_src = BTreeSet::new();
    let mut acl_dst = BTreeSet::new();
    for rule in &state.rules {
        insert_reference(&mut acl_src, rule.src_group_id);
        insert_reference(&mut acl_dst, rule.dst_group_id);
    }

    let mut explicit_general = BTreeSet::new();
    for rule in &state.qos_rules {
        insert_reference(&mut explicit_general, rule.group_id);
    }
    for rule in &state.mirror_rules {
        insert_reference(&mut explicit_general, rule.src_group_id);
        insert_reference(&mut explicit_general, rule.dst_group_id);
    }

    for (kind, references) in [
        ("ACL source", &acl_src),
        ("ACL destination", &acl_dst),
        ("QoS/Mirror", &explicit_general),
    ] {
        for group_id in references {
            if !groups.contains_key(group_id) {
                return Err(format!(
                    "missing persisted group ID {} referenced by {} state",
                    group_id, kind
                ));
            }
        }
    }

    Ok((acl_src, acl_dst, explicit_general))
}

fn insert_reference(references: &mut BTreeSet<u32>, group_id: u32) {
    if group_id != 0 {
        references.insert(group_id);
    }
}

fn compile_acl_direction(
    label: &str,
    group_ids: &BTreeSet<u32>,
    groups: &BTreeMap<u32, PersistedGroup>,
) -> Result<Vec<ProjectionEntry>, String> {
    let entries = entries_for_ids(group_ids, groups);
    for (index, left) in entries.iter().enumerate() {
        for right in entries.iter().skip(index + 1) {
            if left.group_id != right.group_id && left.network.overlaps(&right.network) {
                return Err(format!(
                    "ACL {} selector overlap between group IDs {} ({}) and {} ({})",
                    label, left.group_id, left.network, right.group_id, right.network
                ));
            }
        }
    }
    Ok(entries)
}

fn entries_for_ids(
    group_ids: &BTreeSet<u32>,
    groups: &BTreeMap<u32, PersistedGroup>,
) -> Vec<ProjectionEntry> {
    group_ids
        .iter()
        .flat_map(|group_id| {
            groups
                .get(group_id)
                .expect("group references were validated before projection")
                .networks
                .iter()
                .map(|network| ProjectionEntry {
                    network: *network,
                    group_id: *group_id,
                })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn select_highest_exact_winners(entries: Vec<ProjectionEntry>) -> Vec<ProjectionEntry> {
    let mut winners = BTreeMap::new();
    for entry in entries {
        winners
            .entry(entry.network)
            .and_modify(|group_id: &mut u32| *group_id = (*group_id).max(entry.group_id))
            .or_insert(entry.group_id);
    }
    winners
        .into_iter()
        .map(|(network, group_id)| ProjectionEntry { network, group_id })
        .collect()
}

fn describe_general_candidates(
    groups: &BTreeMap<u32, PersistedGroup>,
    acl_only_ids: &BTreeSet<u32>,
    general_domain_winners: &[ProjectionEntry],
    general: &[ProjectionEntry],
) -> Vec<GeneralProjectionCandidate> {
    let winners: BTreeMap<CanonicalNetwork, ProjectionEntry> = general
        .iter()
        .map(|entry| (entry.network, *entry))
        .collect();
    let mut candidates = Vec::new();
    for group in groups.values() {
        for network in &group.networks {
            let entry = ProjectionEntry {
                network: *network,
                group_id: group.id,
            };
            let disposition = if acl_only_ids.contains(&group.id) {
                match most_specific_covering_entry(network, general_domain_winners) {
                    Some(covering) => GeneralProjectionDisposition::Excluded(
                        GeneralProjectionExclusionReason::CoveredByGeneralDomain { covering },
                    ),
                    None => exact_winner_disposition(entry, &winners),
                }
            } else {
                exact_winner_disposition(entry, &winners)
            };
            candidates.push(GeneralProjectionCandidate {
                entry,
                stable_group_identity: group.stable_name.clone(),
                disposition,
            });
        }
    }
    candidates.sort();
    candidates
}

fn exact_winner_disposition(
    entry: ProjectionEntry,
    winners: &BTreeMap<CanonicalNetwork, ProjectionEntry>,
) -> GeneralProjectionDisposition {
    match winners.get(&entry.network) {
        Some(winner) if winner == &entry => GeneralProjectionDisposition::Included,
        Some(winner) => {
            GeneralProjectionDisposition::Excluded(GeneralProjectionExclusionReason::ExactKeyLost {
                winner: *winner,
            })
        }
        None => unreachable!("every non-shadowed candidate has an exact general winner"),
    }
}

fn most_specific_covering_entry(
    network: &CanonicalNetwork,
    candidates: &[ProjectionEntry],
) -> Option<ProjectionEntry> {
    candidates
        .iter()
        .filter(|candidate| candidate.network.contains(network))
        .max_by_key(|candidate| (candidate.network.prefix_len(), candidate.group_id))
        .copied()
}

fn legacy_candidate_index(
    projection: &ManagedGroupProjection,
) -> BTreeMap<CanonicalNetwork, BTreeSet<u32>> {
    let mut candidates: BTreeMap<CanonicalNetwork, BTreeSet<u32>> = BTreeMap::new();
    for entry in &projection.legacy_candidates {
        candidates
            .entry(entry.network)
            .or_default()
            .insert(entry.group_id);
    }
    candidates
}

fn normalize_entries(
    entries: &[ProjectionEntry],
    label: &str,
) -> Result<BTreeMap<CanonicalNetwork, u32>, String> {
    let mut normalized = BTreeMap::new();
    for entry in entries {
        if let Some(existing) = normalized.insert(entry.network, entry.group_id) {
            if existing != entry.group_id {
                return Err(format!(
                    "{} contains conflicting values {} and {} for key {}",
                    label, existing, entry.group_id, entry.network
                ));
            }
        }
    }
    Ok(normalized)
}

fn classify_map_drift(
    label: &str,
    actual: &BTreeMap<CanonicalNetwork, u32>,
    expected: &BTreeMap<CanonicalNetwork, u32>,
    candidates: &BTreeMap<CanonicalNetwork, BTreeSet<u32>>,
) -> Result<bool, String> {
    let mut repair_required = false;

    for (network, actual_group_id) in actual {
        let Some(candidate_ids) = candidates.get(network) else {
            return Err(format!(
                "{} contains unknown runtime key {} with group ID {}",
                label, network, actual_group_id
            ));
        };
        if !candidate_ids.contains(actual_group_id) {
            return Err(format!(
                "{} contains unknown group ID {} for persisted key {}",
                label, actual_group_id, network
            ));
        }
        if expected.get(network) != Some(actual_group_id) {
            repair_required = true;
        }
    }

    for (network, expected_group_id) in expected {
        if actual.contains_key(network) {
            continue;
        }
        let candidate_count = candidates.get(network).map_or(0, BTreeSet::len);
        if candidate_count < 2 {
            return Err(format!(
                "{} is missing unexplained persisted key {} for group ID {}",
                label, network, expected_group_id
            ));
        }
        repair_required = true;
    }

    Ok(repair_required)
}

fn build_general_mutations(
    captured_src: &BTreeMap<CanonicalNetwork, u32>,
    captured_dst: &BTreeMap<CanonicalNetwork, u32>,
    proposed: &BTreeMap<CanonicalNetwork, u32>,
) -> Vec<ProjectionMutation> {
    let mut upserts = Vec::new();
    let mut deletes = Vec::new();
    for (direction, captured) in [
        (ProjectionDirection::Src, captured_src),
        (ProjectionDirection::Dst, captured_dst),
    ] {
        let keys: BTreeSet<CanonicalNetwork> =
            captured.keys().chain(proposed.keys()).copied().collect();
        for network in keys {
            match (captured.get(&network), proposed.get(&network)) {
                (None, Some(group_id)) => upserts.push(ProjectionMutation::Added {
                    direction,
                    entry: ProjectionEntry {
                        network,
                        group_id: *group_id,
                    },
                }),
                (Some(old_group_id), Some(new_group_id)) if old_group_id != new_group_id => {
                    upserts.push(ProjectionMutation::Replaced {
                        direction,
                        network,
                        old_group_id: *old_group_id,
                        new_group_id: *new_group_id,
                    });
                }
                (Some(group_id), None) => deletes.push(ProjectionMutation::Deleted {
                    direction,
                    entry: ProjectionEntry {
                        network,
                        group_id: *group_id,
                    },
                }),
                _ => {}
            }
        }
    }
    upserts.extend(deletes);
    upserts
}
