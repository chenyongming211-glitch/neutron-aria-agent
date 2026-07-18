use crate::control_plane::{ControlPlane, ControlPlaneError, MANAGED_SHARED_PIN_NAMESPACE};
use crate::instance::FirewallInstance;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeReconcileResult {
    pub ifname: String,
    pub action: String,
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ManagedAttachMode {
    StandaloneRestoreAfterTcAttach,
    NeutronResyncRequired { acl_managed: bool },
}

async fn complete_managed_registration_transaction<
    T,
    Failure,
    FailureFuture,
    Success,
    SuccessFuture,
>(
    activation: Result<(), String>,
    transaction: T,
    on_failure: Failure,
    on_success: Success,
) -> Result<(), String>
where
    Failure: FnOnce(T, String) -> FailureFuture,
    FailureFuture: std::future::Future<Output = Result<(), String>>,
    Success: FnOnce(T) -> SuccessFuture,
    SuccessFuture: std::future::Future<Output = Result<(), String>>,
{
    match activation {
        Ok(()) => on_success(transaction).await,
        Err(error) => on_failure(transaction, error).await,
    }
}

pub struct TapRegistry {
    instances: RwLock<HashMap<String, FirewallInstance>>,
    /// Per-iface mutex to serialize attach/detach on the same interface
    iface_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
    pub ebpf_path: PathBuf,
    pub base_pin_path: PathBuf,
    pub base_state_path: PathBuf,
    pub iface_pattern: Regex,
    pub max_port_policies: u32,
    control_plane: Arc<ControlPlane>,
}

impl TapRegistry {
    pub fn new(
        ebpf_path: &str,
        base_pin_path: &str,
        base_state_path: &str,
        iface_pattern: &str,
        max_port_policies: u32,
        control_plane: Arc<ControlPlane>,
    ) -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            iface_locks: RwLock::new(HashMap::new()),
            ebpf_path: PathBuf::from(ebpf_path),
            base_pin_path: PathBuf::from(base_pin_path),
            base_state_path: PathBuf::from(base_state_path),
            iface_pattern: Regex::new(iface_pattern)
                .unwrap_or_else(|_| Regex::new("^tap").unwrap()),
            max_port_policies,
            control_plane,
        }
    }

    /// Get or create the per-iface mutex for serializing operations
    async fn get_iface_lock(&self, iface: &str) -> Arc<Mutex<()>> {
        let locks = self.iface_locks.read().await;
        if let Some(lock) = locks.get(iface) {
            return lock.clone();
        }
        drop(locks);

        let mut locks = self.iface_locks.write().await;
        locks
            .entry(iface.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Check if the interface name matches the configured pattern
    pub fn matches_pattern(&self, iface: &str) -> bool {
        self.iface_pattern.is_match(iface)
    }

    fn cleanup_shared_runtime_dir(&self) {
        let shared_pin_path = self.base_pin_path.join(MANAGED_SHARED_PIN_NAMESPACE);
        if shared_pin_path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&shared_pin_path) {
                warn!(
                    path = %shared_pin_path.display(),
                    error = %e,
                    "failed to remove shared managed pin directory"
                );
            } else {
                info!(path = %shared_pin_path.display(), "removed shared managed pin directory");
            }
        }
    }

    fn managed_link_pin_ifaces(&self) -> Result<BTreeSet<String>, String> {
        let shared_pin_path = self.base_pin_path.join(MANAGED_SHARED_PIN_NAMESPACE);
        let mut ifaces = BTreeSet::new();
        if !shared_pin_path.exists() {
            return Ok(ifaces);
        }
        let entries = std::fs::read_dir(&shared_pin_path)
            .map_err(|e| format!("read managed pin dir {}: {}", shared_pin_path.display(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read managed pin entry: {}", e))?;
            let name = entry.file_name().to_string_lossy().to_string();
            for suffix in ["_xdp_link", "_tc_egress_link", "_tc_ingress_link"] {
                if let Some(ifname) = name.strip_suffix(suffix) {
                    if !ifname.is_empty() {
                        ifaces.insert(ifname.to_string());
                    }
                    break;
                }
            }
        }
        Ok(ifaces)
    }

    fn remove_orphaned_managed_link_pins(&self, ifname: &str) -> Result<(), String> {
        let shared_pin_path = self.base_pin_path.join(MANAGED_SHARED_PIN_NAMESPACE);
        let mut errors = Vec::new();
        for suffix in ["xdp", "tc_egress", "tc_ingress"] {
            let path = shared_pin_path.join(format!("{}_{}_link", ifname, suffix));
            if !path.exists() {
                continue;
            }
            if let Err(e) = std::fs::remove_file(&path) {
                errors.push(format!("remove {}: {}", path.display(), e));
            }
        }

        let instance = FirewallInstance::new(
            ifname,
            PathBuf::from(self.control_plane.managed_pin_path()),
            self.base_state_path.join(ifname),
            true,
            self.control_plane.trace_map_mode(),
        );
        if let Err(e) = instance.release_persisted_live_iface() {
            errors.push(format!("release persisted live iface: {}", e));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Reconcile actual pinned managed runtime against Neutron WAL committed ports.
    ///
    /// This claims/rebuilds committed interfaces through the normal attach path,
    /// then removes pinned link orphans that are not present in the committed set.
    pub async fn reconcile_neutron_runtime(
        &self,
        committed_ifaces: &[(String, bool)],
    ) -> Vec<RuntimeReconcileResult> {
        let mut committed = BTreeMap::new();
        for (ifname, acl_managed) in committed_ifaces {
            if ifname.trim().is_empty() {
                continue;
            }
            committed
                .entry(ifname.clone())
                .and_modify(|managed| *managed |= *acl_managed)
                .or_insert(*acl_managed);
        }
        let committed_names: BTreeSet<String> = committed.keys().cloned().collect();
        let pinned_ifaces = match self.managed_link_pin_ifaces() {
            Ok(ifaces) => ifaces,
            Err(e) => {
                return vec![RuntimeReconcileResult {
                    ifname: String::new(),
                    action: "inventory".to_string(),
                    status: "blocked".to_string(),
                    reason: Some(e),
                }];
            }
        };

        let mut results = Vec::new();
        for (ifname, acl_managed) in &committed {
            match self.attach_neutron(ifname, *acl_managed).await {
                Ok(()) => results.push(RuntimeReconcileResult {
                    ifname: ifname.clone(),
                    action: "claim_committed".to_string(),
                    status: "ready".to_string(),
                    reason: Some("runtime_reconciled".to_string()),
                }),
                Err(e) => results.push(RuntimeReconcileResult {
                    ifname: ifname.clone(),
                    action: "claim_committed".to_string(),
                    status: "blocked".to_string(),
                    reason: Some(format!("runtime_reconcile_failed:{}", e)),
                }),
            }
        }

        for ifname in pinned_ifaces.difference(&committed_names) {
            let _runtime_guard = self.control_plane.lock_runtime_lifecycle().await;
            match self.remove_orphaned_managed_link_pins(ifname) {
                Ok(()) => results.push(RuntimeReconcileResult {
                    ifname: ifname.clone(),
                    action: "cleanup_orphan".to_string(),
                    status: "cleaned".to_string(),
                    reason: Some("orphaned_pinned_links_removed".to_string()),
                }),
                Err(e) => results.push(RuntimeReconcileResult {
                    ifname: ifname.clone(),
                    action: "cleanup_orphan".to_string(),
                    status: "blocked".to_string(),
                    reason: Some(format!("orphan_cleanup_failed:{}", e)),
                }),
            }
        }

        results
    }

    /// Attach XDP firewall to a tap interface. Idempotent: skips if already attached.
    pub async fn attach(&self, iface: &str) -> Result<(), String> {
        self.attach_with_mode(iface, ManagedAttachMode::StandaloneRestoreAfterTcAttach)
            .await
    }

    pub async fn attach_neutron(&self, iface: &str, acl_managed: bool) -> Result<(), String> {
        self.attach_with_mode(
            iface,
            ManagedAttachMode::NeutronResyncRequired { acl_managed },
        )
        .await
    }

    pub async fn update_neutron_acl_runtime_gate(
        &self,
        instance: &str,
        conntrack_enabled: bool,
        acl_enabled: bool,
        allow_recovery_publication: bool,
    ) -> Result<(), ControlPlaneError> {
        let _runtime_guard = self.control_plane.lock_runtime_lifecycle().await;
        self.control_plane
            .update_neutron_acl_runtime_gate_serialized(
                instance,
                conntrack_enabled,
                acl_enabled,
                allow_recovery_publication,
            )
            .await
    }

    async fn attach_with_mode(&self, iface: &str, mode: ManagedAttachMode) -> Result<(), String> {
        // This fast presence read is advisory only. Existing registrations may
        // still require an ownership promotion under the serialized locks.
        let _existing_registration = {
            let instances = self.instances.read().await;
            instances.contains_key(iface)
        };

        let iface_lock = self.get_iface_lock(iface).await;
        let _guard = iface_lock.lock().await;
        let _runtime_guard = self.control_plane.lock_runtime_lifecycle().await;

        // Re-check after acquiring lock
        let already_attached = {
            let instances = self.instances.read().await;
            instances.contains_key(iface)
        };
        if already_attached {
            return self
                .control_plane
                .promote_managed_acl_ownership_serialized(iface, mode)
                .await;
        }

        let known_live_runtime = {
            let instances = self.instances.read().await;
            !instances.is_empty()
        };

        let mut instance = FirewallInstance::new(
            iface,
            PathBuf::from(self.control_plane.managed_pin_path()),
            self.base_state_path.join(iface),
            true,
            self.control_plane.trace_map_mode(),
        );

        // 为该 tap 实例设置端口策略上限（写入对应 state.json）
        let state_dir = self.base_state_path.join(iface);
        if let Some(state_str) = state_dir.to_str() {
            let sm = aria_core::state::StateManager::new(state_str);
            if let Err(e) = sm.set_max_port_policies(self.max_port_policies) {
                warn!(instance = %iface, error = %e, "failed to persist max_port_policies");
            }
        }

        let ebpf_path = self
            .ebpf_path
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 ebpf path: {}", self.ebpf_path.display()))?;
        let runtime_pin = instance.ensure_runtime_pinned(ebpf_path, known_live_runtime)?;

        let prepared = match self
            .control_plane
            .prepare_managed_registration(iface, &runtime_pin, mode)
            .await
        {
            Ok(prepared) => prepared,
            Err(e) => {
                if runtime_pin.created_shared_runtime {
                    self.cleanup_shared_runtime_dir();
                }
                return Err(format!("control-plane prepare failed: {}", e));
            }
        };

        if let Err(e) = instance.reserve_persisted_live_iface() {
            let quiesce_error = self
                .control_plane
                .quiesce_managed_registration(&prepared)
                .err();
            self.control_plane
                .abort_managed_registration(prepared)
                .await;
            if runtime_pin.created_shared_runtime {
                self.cleanup_shared_runtime_dir();
            }
            return Err(match quiesce_error {
                Some(quiesce_error) => format!(
                    "failed to reserve persisted live runtime state: {}; ACL/CT quiesce failed: {}",
                    e, quiesce_error
                ),
                None => format!("failed to reserve persisted live runtime state: {}", e),
            });
        }

        let attached = match instance.attach_links_from_pinned_runtime(&runtime_pin) {
            Ok(attached) => attached,
            Err(e) => {
                let quiesce_error = self
                    .control_plane
                    .quiesce_managed_registration(&prepared)
                    .err();
                if let Err(release_err) = instance.release_persisted_live_iface() {
                    warn!(instance = %iface, error = %release_err, "failed to roll back persisted live runtime state");
                }
                self.control_plane
                    .abort_managed_registration(prepared)
                    .await;
                if runtime_pin.created_shared_runtime {
                    self.cleanup_shared_runtime_dir();
                }
                return Err(match quiesce_error {
                    Some(quiesce_error) => format!(
                        "interface link attach failed: {}; ACL/CT quiesce failed: {}",
                        e, quiesce_error
                    ),
                    None => format!("interface link attach failed: {}", e),
                });
            }
        };

        if prepared.requires_tc_acl_links() {
            if let Err(e) = instance.require_tc_acl_links() {
                let quiesce_error = self
                    .control_plane
                    .quiesce_managed_registration(&prepared)
                    .err();
                if let Err(rollback_err) = instance.rollback_attached_links(&attached, false) {
                    warn!(instance = %iface, error = %rollback_err, "failed to roll back links after required TC readiness failure");
                }
                if let Err(release_err) = instance.release_persisted_live_iface() {
                    warn!(instance = %iface, error = %release_err, "failed to roll back persisted live runtime state");
                }
                self.control_plane
                    .abort_managed_registration(prepared)
                    .await;
                if runtime_pin.created_shared_runtime {
                    self.cleanup_shared_runtime_dir();
                }
                return Err(match quiesce_error {
                    Some(quiesce_error) => format!(
                        "required TC ACL links unavailable: {}; ACL/CT quiesce failed: {}",
                        e, quiesce_error
                    ),
                    None => format!("required TC ACL links unavailable: {}", e),
                });
            }
        }

        let activation = self
            .control_plane
            .activate_managed_registration(&prepared)
            .await;
        complete_managed_registration_transaction(
            activation,
            (
                prepared,
                instance,
                attached,
                runtime_pin.created_shared_runtime,
            ),
            |(prepared, instance, attached, created_shared_runtime), error| async move {
                let quiesce_error = self
                    .control_plane
                    .quiesce_managed_registration(&prepared)
                    .err();
                if let Err(rollback_err) = instance.rollback_attached_links(&attached, false) {
                    warn!(instance = %iface, error = %rollback_err, "failed to roll back links after managed runtime activation failure");
                }
                if let Err(release_err) = instance.release_persisted_live_iface() {
                    warn!(instance = %iface, error = %release_err, "failed to roll back persisted live runtime state");
                }
                self.control_plane
                    .abort_managed_registration(prepared)
                    .await;
                if created_shared_runtime {
                    self.cleanup_shared_runtime_dir();
                }
                Err(match quiesce_error {
                    Some(quiesce_error) => format!(
                        "managed runtime activation failed: {}; ACL/CT quiesce failed: {}",
                        error, quiesce_error
                    ),
                    None => format!("managed runtime activation failed: {}", error),
                })
            },
            |(prepared, instance, _attached, _created_shared_runtime)| async move {
                self.control_plane.publish_managed_instance(prepared).await;

                let mut instances = self.instances.write().await;
                instances.insert(iface.to_string(), instance);
                Ok(())
            },
        )
        .await
    }

    /// Detach XDP firewall from a tap interface.
    pub async fn detach(&self, iface: &str) -> Result<(), String> {
        let iface_lock = self.get_iface_lock(iface).await;
        let _guard = iface_lock.lock().await;
        let _runtime_guard = self.control_plane.lock_runtime_lifecycle().await;

        let instance_exists = {
            let instances = self.instances.read().await;
            instances.contains_key(iface)
        };

        if instance_exists {
            let instances = self.instances.read().await;
            if let Some(instance) = instances.get(iface) {
                instance.detach()?;
                if let Err(e) = instance.release_persisted_live_iface() {
                    warn!(instance = %iface, error = %e, "failed to release persisted live runtime state");
                }
            } else {
                warn!(instance = %iface, "instance disappeared before detach");
            }
        }

        {
            let mut instances = self.instances.write().await;
            instances.remove(iface);
        }

        self.control_plane.unregister_instance(iface).await;

        let should_cleanup_shared_runtime = {
            let instances = self.instances.read().await;
            instances.is_empty()
        };

        if should_cleanup_shared_runtime {
            self.cleanup_shared_runtime_dir();
        }

        // Clean up the per-iface lock
        let mut locks = self.iface_locks.write().await;
        locks.remove(iface);

        Ok(())
    }

    /// List all managed tap interfaces
    pub async fn list(&self) -> Vec<String> {
        let instances = self.instances.read().await;
        let mut names: Vec<String> = instances.keys().cloned().collect();
        names.sort();
        names
    }

    /// Graceful shutdown: unpin all links (XDP detaches), clean up
    pub async fn shutdown(&self) {
        let ifaces: Vec<String> = {
            let instances = self.instances.read().await;
            instances.keys().cloned().collect()
        };

        for iface in &ifaces {
            if let Err(e) = self.detach(iface).await {
                warn!(instance = %iface, error = %e, "shutdown detach failed");
            }
        }
        info!("all firewall instances detached");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::{
        managed_acl_ownership_after_detach, managed_acl_promotion_action,
        managed_neutron_authority_confirmation_allowed, ManagedAclPromotionAction,
        ManagedAclPublicationMode, ManagedProjectionHealth,
    };

    #[derive(Default)]
    struct TestManagedTransactionState {
        control_plane_instances: BTreeSet<String>,
        tap_instances: BTreeSet<String>,
        rollback_count: usize,
        release_count: usize,
        abort_count: usize,
    }

    #[tokio::test]
    async fn managed_failure_path_activation_failure_leaves_real_registries_empty() {
        let state = Arc::new(Mutex::new(TestManagedTransactionState::default()));
        let failure_state = state.clone();
        let publish_state = state.clone();

        let error = complete_managed_registration_transaction(
            Err("forced activation failure".to_string()),
            "tap-failed".to_string(),
            move |_iface, activation_error| async move {
                let mut state = failure_state.lock().await;
                state.rollback_count += 1;
                state.release_count += 1;
                state.abort_count += 1;
                Err(format!(
                    "managed runtime activation failed: {}",
                    activation_error
                ))
            },
            move |iface| async move {
                let mut state = publish_state.lock().await;
                state.control_plane_instances.insert(iface.clone());
                state.tap_instances.insert(iface);
                Ok(())
            },
        )
        .await
        .unwrap_err();

        assert!(error.contains("forced activation failure"));
        let state = state.lock().await;
        assert!(state.control_plane_instances.is_empty());
        assert!(state.tap_instances.is_empty());
        assert_eq!(state.rollback_count, 1);
        assert_eq!(state.release_count, 1);
        assert_eq!(state.abort_count, 1);
    }

    #[test]
    fn managed_acl_ownership_existing_standalone_attach_promotes_to_managed_unverified() {
        for publication_mode in [
            ManagedAclPublicationMode::StandaloneCompatibility,
            ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,
        ] {
            let action = managed_acl_promotion_action(
                publication_mode,
                ManagedProjectionHealth::Unverified,
                ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
            );

            assert_eq!(
                action,
                ManagedAclPromotionAction::Promote {
                    next_mode: ManagedAclPublicationMode::ManagedAcl,
                    next_health: ManagedProjectionHealth::Unverified,
                    quiesce_acl_ct: true,
                },
                "an existing {:?} attach must not swallow managed ACL promotion",
                publication_mode
            );
        }
    }

    #[test]
    fn managed_projection_attach_repair_managed_attach_only_requests_explicit_demotion() {
        for projection_health in [
            ManagedProjectionHealth::Verified,
            ManagedProjectionHealth::Unverified,
            ManagedProjectionHealth::RepairRequired,
        ] {
            assert_eq!(
                managed_acl_promotion_action(
                    ManagedAclPublicationMode::ManagedAcl,
                    projection_health,
                    ManagedAttachMode::NeutronResyncRequired { acl_managed: false },
                ),
                ManagedAclPromotionAction::Demote {
                    next_mode: ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,
                    next_health: ManagedProjectionHealth::Unverified,
                },
                "managed ACL ownership must not silently preserve when ACL leaves the requested domains"
            );
        }
    }

    #[test]
    fn managed_acl_ownership_repeated_managed_attach_preserves_verified_idempotence() {
        let action = managed_acl_promotion_action(
            ManagedAclPublicationMode::ManagedAcl,
            ManagedProjectionHealth::Verified,
            ManagedAttachMode::NeutronResyncRequired { acl_managed: true },
        );

        assert_eq!(action, ManagedAclPromotionAction::Preserve);
    }

    #[test]
    fn managed_acl_ownership_detach_clears_attach_and_acl_ownership() {
        for (publication_mode, projection_health) in [
            (
                ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl,
                ManagedProjectionHealth::Unverified,
            ),
            (
                ManagedAclPublicationMode::ManagedAcl,
                ManagedProjectionHealth::RepairRequired,
            ),
            (
                ManagedAclPublicationMode::ManagedAcl,
                ManagedProjectionHealth::Verified,
            ),
        ] {
            let remaining = managed_acl_ownership_after_detach(publication_mode, projection_health);

            assert_eq!(
                remaining, None,
                "detach must clear both attach and ACL ownership from {:?}/{:?}",
                publication_mode, projection_health
            );
        }
    }

    #[test]
    fn managed_acl_ownership_authority_confirmation_rejects_detached_instance() {
        assert!(!managed_neutron_authority_confirmation_allowed(
            false,
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedProjectionHealth::Verified),
            Some(ManagedProjectionHealth::Verified),
        ));
        assert!(!managed_neutron_authority_confirmation_allowed(
            false, None, None, None, None,
        ));
    }

    #[test]
    fn managed_acl_ownership_authority_confirmation_revalidates_projection_health() {
        assert!(!managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedProjectionHealth::Unverified),
            Some(ManagedProjectionHealth::Verified),
        ));
        assert!(!managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedAclPublicationMode::ManagedAcl),
            None,
            Some(ManagedProjectionHealth::Verified),
        ));
        assert!(managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedProjectionHealth::Verified),
            Some(ManagedProjectionHealth::Verified),
        ));
        assert!(!managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::StandaloneCompatibility),
            None,
            None,
            None,
        ));
        assert!(managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::NeutronAttachOwnedStandaloneAcl),
            None,
            None,
            None,
        ));
        assert!(managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::ManagedAcl),
            None,
            Some(ManagedProjectionHealth::Unverified),
            None,
        ));
    }

    #[test]
    fn managed_acl_ownership_authority_confirmation_revalidates_publication_mode() {
        assert!(!managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::StandaloneCompatibility),
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedProjectionHealth::Unverified),
            None,
        ));
        assert!(managed_neutron_authority_confirmation_allowed(
            true,
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedAclPublicationMode::ManagedAcl),
            Some(ManagedProjectionHealth::Unverified),
            None,
        ));
    }
}
