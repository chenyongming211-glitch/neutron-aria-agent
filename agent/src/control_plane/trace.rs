use super::*;

impl ControlPlane {
    // ── Packet Trace ──

    pub async fn start_trace(
        &self,
        instance: &str,
        src_ip: u32,
        dst_ip: u32,
        src_ip_v6: [u8; 16],
        dst_ip_v6: [u8; 16],
        src_port: u16,
        dst_port: u16,
        proto: u8,
        is_ipv6: u8,
    ) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::trace_ops::set_trace_filter(
            state.map_runtime(),
            src_ip,
            dst_ip,
            src_ip_v6,
            dst_ip_v6,
            src_port,
            dst_port,
            proto,
            is_ipv6,
            true,
        )
        .map_err(ControlPlaneError::KernelError)
    }

    pub async fn stop_trace(&self, instance: &str) -> Result<(), ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::trace_ops::clear_trace_filter(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn get_trace_events(
        &self,
        instance: &str,
        limit: usize,
    ) -> Result<
        (
            Vec<aria_core::trace_ops::TraceEventEntry>,
            HashMap<String, GroupInfo>,
        ),
        ControlPlaneError,
    > {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        let events = self
            .trace_manager
            .get_trace_events(state.map_runtime(), limit)
            .await
            .map_err(ControlPlaneError::KernelError)?;
        Ok((events, state.state.groups.clone()))
    }

    pub async fn flush_trace(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        self.trace_manager
            .flush_trace_events(state.map_runtime())
            .await
            .map_err(ControlPlaneError::KernelError)
    }
}
