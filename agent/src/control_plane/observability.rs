use super::*;

fn unique_fragment_runtime_paths<I, S>(paths: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    paths
        .into_iter()
        .map(Into::into)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl ControlPlane {
    // ── Stats ──

    pub async fn get_stats_overview(
        &self,
        instance: &str,
    ) -> Result<(usize, usize, usize, usize, u64, u64), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;

        let ct_summary = aria_core::monitoring::get_conntrack_stats(state.map_runtime()).unwrap_or(
            aria_core::monitoring::ConntrackSummary {
                total_v4: 0,
                total_v6: 0,
                new_count: 0,
                established_count: 0,
            },
        );

        Ok((
            state.state.groups.len(),
            state.state.rules.len(),
            state.state.qos_rules.len(),
            state.state.mirror_rules.len(),
            ct_summary.total_v4,
            ct_summary.total_v6,
        ))
    }

    pub async fn get_ct_contract_stats(
        &self,
        instance: &str,
    ) -> Result<Vec<aria_core::ct_contract_ops::CtContractStatsEntry>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::ct_contract_ops::get_ct_contract_stats(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn get_rule_stats(
        &self,
        instance: &str,
    ) -> Result<
        (
            Vec<aria_core::monitoring::RuleStatsEntry>,
            HashMap<String, GroupInfo>,
        ),
        ControlPlaneError,
    > {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_rule_stats(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        Ok((stats, state.state.groups.clone()))
    }

    pub async fn get_top_flows(
        &self,
        instance: &str,
        top: usize,
    ) -> Result<
        (
            Vec<aria_core::monitoring::FlowStatsEntry>,
            Vec<aria_core::monitoring::FlowStatsEntryV6>,
        ),
        ControlPlaneError,
    > {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let v4 = aria_core::monitoring::get_top_flows_v4(state.map_runtime(), top)
            .map_err(ControlPlaneError::KernelError)?;
        let v6 = aria_core::monitoring::get_top_flows_v6(state.map_runtime(), top)
            .map_err(ControlPlaneError::KernelError)?;
        Ok((v4, v6))
    }

    pub async fn get_qos_stats(
        &self,
        instance: &str,
    ) -> Result<
        (
            Vec<aria_core::monitoring::QosStatsEntry>,
            HashMap<String, GroupInfo>,
        ),
        ControlPlaneError,
    > {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_qos_stats(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        Ok((stats, state.state.groups.clone()))
    }

    pub async fn get_group_stats(
        &self,
        instance: &str,
    ) -> Result<
        (
            Vec<aria_core::monitoring::GroupStatsEntry>,
            HashMap<String, GroupInfo>,
        ),
        ControlPlaneError,
    > {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::monitoring::get_group_stats(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        Ok((stats, state.state.groups.clone()))
    }

    // ── Drop Reason Profiler ──

    pub async fn get_drop_stats(
        &self,
        instance: &str,
    ) -> Result<
        (
            Vec<aria_core::drop_ops::DropStatsEntry>,
            HashMap<String, GroupInfo>,
        ),
        ControlPlaneError,
    > {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let stats = aria_core::drop_ops::get_drop_stats(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)?;
        Ok((stats, state.state.groups.clone()))
    }

    pub async fn flush_drop_stats(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::drop_ops::flush_drop_stats(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn get_kernel_drop_stats(
        &self,
        query: &aria_api::KernelDropQuery,
    ) -> Result<Vec<aria_api::KernelDropStatsEntry>, ControlPlaneError> {
        let status = self.kernel_drop_manager.status_snapshot().await;
        if !status.loaded {
            return Err(ControlPlaneError::InstanceNotReady(
                "kernel drop observability is not available".to_string(),
            ));
        }

        let resolved = self.resolve_kernel_drop_query(query).await?;

        let entries = aria_core::kernel_drop_ops::get_kernel_drop_stats(
            self.kernel_drop_manager.pin_path(),
            &aria_core::kernel_drop_ops::KernelDropQuery {
                tap_id: resolved.tap_id,
                ifindex: resolved.ifindex,
                reason_code: query.reason,
                top: query.top,
                include_unattributed: resolved.include_unattributed,
            },
        )
        .map_err(ControlPlaneError::KernelError)?;

        let reason_names = self.kernel_drop_manager.reason_names_snapshot().await;

        Ok(entries
            .into_iter()
            .map(|entry| {
                let reason = match entry.reason_code {
                    Some(c) => reason_names
                        .get(&c)
                        .cloned()
                        .unwrap_or_else(|| format!("reason_{}", c)),
                    None => "unknown".to_string(),
                };
                let (location, location_hint) = self
                    .kernel_drop_manager
                    .resolve_location(entry.last_location);
                aria_api::KernelDropStatsEntry {
                    instance: if entry.ifindex == 0 {
                        None
                    } else {
                        resolved
                            .by_ifindex
                            .get(&entry.ifindex)
                            .cloned()
                            .or_else(|| resolved.by_tap.get(&entry.tap_id).cloned())
                    },
                    iface: if entry.ifindex == 0 {
                        None
                    } else {
                        resolved.iface_name_by_ifindex.get(&entry.ifindex).cloned()
                    },
                    ifindex: entry.ifindex,
                    reason_code: entry.reason_code,
                    reason,
                    proto: aria_core::kernel_drop_ops::kernel_drop_proto_name(entry.proto),
                    packets: entry.packets,
                    bytes: entry.bytes,
                    last_seen_ns: entry.last_seen_ns,
                    last_location: entry.last_location,
                    location,
                    location_hint,
                    source: entry.source,
                }
            })
            .collect())
    }

    pub async fn flush_kernel_drop_stats(
        &self,
        query: &aria_api::KernelDropQuery,
    ) -> Result<u64, ControlPlaneError> {
        let status = self.kernel_drop_manager.status_snapshot().await;
        if !status.loaded {
            return Err(ControlPlaneError::InstanceNotReady(
                "kernel drop observability is not available".to_string(),
            ));
        }

        let resolved = self.resolve_kernel_drop_query(query).await?;

        aria_core::kernel_drop_ops::flush_kernel_drop_stats(
            self.kernel_drop_manager.pin_path(),
            &aria_core::kernel_drop_ops::KernelDropQuery {
                tap_id: resolved.tap_id,
                ifindex: resolved.ifindex,
                reason_code: query.reason,
                top: query.top,
                include_unattributed: resolved.include_unattributed,
            },
        )
        .map_err(ControlPlaneError::KernelError)
    }

    pub async fn get_kernel_drop_status(&self) -> KernelDropStatusSnapshot {
        self.kernel_drop_manager.status_snapshot().await
    }

    pub async fn get_fragment_metrics(
        &self,
    ) -> Vec<(String, aria_core::monitoring::FragmentMetricsSummary)> {
        let instances: Vec<_> = {
            let instances = self.instances.read().await;
            instances.values().cloned().collect()
        };
        let mut runtime_paths = Vec::with_capacity(instances.len());
        for instance in instances {
            runtime_paths.push(instance.read().await.pin_path.clone());
        }

        unique_fragment_runtime_paths(runtime_paths)
            .into_iter()
            .map(|pin_path| {
                let summary = aria_core::monitoring::get_fragment_metrics_summary(&pin_path);
                for error in &summary.warnings {
                    warn!(
                        pin_path = %pin_path,
                        error = %error,
                        "omitting unavailable fragment metric series"
                    );
                }
                (pin_path, summary)
            })
            .collect()
    }
}

#[cfg(test)]
mod fragment_metrics_tests {
    use super::unique_fragment_runtime_paths;

    #[test]
    fn fragment_loader_metrics_aggregate_each_runtime_pin_path_once() {
        let paths = unique_fragment_runtime_paths([
            "/sys/fs/bpf/aria/global-v2",
            "/sys/fs/bpf/aria/tap-a",
            "/sys/fs/bpf/aria/global-v2",
            "/sys/fs/bpf/aria/tap-b",
            "/sys/fs/bpf/aria/tap-a",
        ]);

        assert_eq!(
            paths,
            vec![
                "/sys/fs/bpf/aria/global-v2".to_string(),
                "/sys/fs/bpf/aria/tap-a".to_string(),
                "/sys/fs/bpf/aria/tap-b".to_string(),
            ]
        );
    }
}
