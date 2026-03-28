use super::*;

impl ControlPlane {
    // ── SSL ──

    pub async fn list_ssl(
        &self,
        instance: &str,
        top: usize,
    ) -> Result<Vec<aria_core::ssl_ops::SslConnEntry>, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.list_ssl_global(top).await
    }

    pub async fn list_ssl_global(
        &self,
        top: usize,
    ) -> Result<Vec<aria_core::ssl_ops::SslConnEntry>, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        let mut entries = aria_core::ssl_ops::get_ssl_conns(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)?;
        entries.truncate(top);
        Ok(entries)
    }

    pub async fn get_ssl_metrics_summary(
        &self,
    ) -> Result<Option<aria_core::ssl_ops::SslMetricsSummary>, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_metrics_summary(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn flush_ssl(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.flush_ssl_global().await
    }

    pub async fn flush_ssl_global(&self) -> Result<u64, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::flush_ssl_conns(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }

    // ── SSL HTTP ──

    pub async fn list_ssl_http(
        &self,
        instance: &str,
        top: usize,
    ) -> Result<Vec<aria_core::ssl_ops::SslHttpEntry>, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.list_ssl_http_global(top).await
    }

    pub async fn list_ssl_http_global(
        &self,
        top: usize,
    ) -> Result<Vec<aria_core::ssl_ops::SslHttpEntry>, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        let mut entries = aria_core::ssl_ops::get_ssl_http_events(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)?;
        entries.truncate(top);
        Ok(entries)
    }

    pub async fn get_ssl_http_metrics_summary(
        &self,
    ) -> Result<Option<aria_core::ssl_ops::SslHttpMetricsSummary>, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::get_ssl_http_metrics_summary(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }

    pub async fn flush_ssl_http(&self, instance: &str) -> Result<u64, ControlPlaneError> {
        self.get_instance(instance).await?;
        self.flush_ssl_http_global().await
    }

    pub async fn flush_ssl_http_global(&self) -> Result<u64, ControlPlaneError> {
        self.ssl_manager
            .ensure_loaded()
            .await
            .map_err(ControlPlaneError::KernelError)?;
        aria_core::ssl_ops::flush_ssl_http_events(self.ssl_manager.pin_path())
            .map_err(ControlPlaneError::KernelError)
    }
}
