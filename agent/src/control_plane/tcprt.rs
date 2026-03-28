use super::*;

impl ControlPlane {
    // ── TCP-RT ──

    pub async fn list_tcprt(
        &self,
        instance: &str,
        top: usize,
    ) -> Result<Vec<aria_core::tcprt_ops::TcpRtEntry>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::monitoring::get_tcprt_stats(state.map_runtime(), top)
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn get_tcprt_metrics_summary(
        &self,
        instance: &str,
    ) -> Result<Option<aria_core::monitoring::TcprtMetricsSummary>, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::monitoring::get_tcprt_metrics_summary(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn flush_tcprt(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        let inst = self.get_instance(instance).await?;
        let state = inst.read().await;
        aria_core::tcprt_ops::flush_tcprt(state.map_runtime())
            .map_err(ControlPlaneError::KernelError)
    }
}
