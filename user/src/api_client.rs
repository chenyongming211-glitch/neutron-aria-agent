use aria_api::*;

pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    // ── Health ──

    pub async fn health(&self) -> Result<HealthResponse, String> {
        let resp = self.client.get(self.url("/api/v1/health"))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Instances ──

    pub async fn list_instances(&self) -> Result<InstancesResponse, String> {
        let resp = self.client.get(self.url("/api/v1/instances"))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── System ──

    pub async fn system_start(&self, req: &SystemStartRequest) -> Result<MessageResponse, String> {
        let resp = self.client.post(self.url("/api/v1/system/start"))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn system_stop(&self) -> Result<MessageResponse, String> {
        let resp = self.client.post(self.url("/api/v1/system/stop"))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Groups ──

    pub async fn list_groups(&self, instance: &str) -> Result<GroupsResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/groups", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_group(&self, instance: &str, req: &AddGroupRequest) -> Result<AddGroupResponse, String> {
        let resp = self.client.post(self.url(&format!("/api/v1/{}/groups", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_group(&self, instance: &str, name: &str) -> Result<MessageResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/groups/{}", instance, name)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Policies ──

    pub async fn list_policies(&self, instance: &str) -> Result<PoliciesResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/policies", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_policy(&self, instance: &str, req: &AddPolicyRequest) -> Result<MessageResponse, String> {
        let resp = self.client.post(self.url(&format!("/api/v1/{}/policies", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_policy(&self, instance: &str, req: &DeletePolicyRequest) -> Result<MessageResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/policies", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn batch_add_policies(&self, instance: &str, req: &BatchAddPoliciesRequest) -> Result<BatchPoliciesResponse, String> {
        let resp = self.client.post(self.url(&format!("/api/v1/{}/policies/batch", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── QoS ──

    pub async fn list_qos(&self, instance: &str) -> Result<QosListResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/qos", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_qos(&self, instance: &str, req: &AddQosRequest) -> Result<MessageResponse, String> {
        let resp = self.client.post(self.url(&format!("/api/v1/{}/qos", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_qos(&self, instance: &str, req: &DeleteQosRequest) -> Result<MessageResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/qos", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Mirror ──

    pub async fn list_mirror(&self, instance: &str) -> Result<MirrorListResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/mirror", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_mirror(&self, instance: &str, req: &AddMirrorRequest) -> Result<MessageResponse, String> {
        let resp = self.client.post(self.url(&format!("/api/v1/{}/mirror", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_mirror(&self, instance: &str, req: &DeleteMirrorRequest) -> Result<MessageResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/mirror", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_mirror(&self, instance: &str) -> Result<MirrorStatsResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/stats/mirror", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Conntrack ──

    pub async fn list_conntrack(&self, instance: &str) -> Result<ConntrackResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/conntrack", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_conntrack(&self, instance: &str) -> Result<ConntrackFlushResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/conntrack", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Config ──

    pub async fn get_config(&self, instance: &str) -> Result<ConfigResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/config", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn update_config(&self, instance: &str, req: &UpdateConfigRequest) -> Result<MessageResponse, String> {
        let resp = self.client.put(self.url(&format!("/api/v1/{}/config", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Stats ──

    pub async fn stats_overview(&self, instance: &str) -> Result<StatsOverview, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/stats", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_rules(&self, instance: &str) -> Result<RuleStatsResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/stats/rules", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_flows(&self, instance: &str, top: usize) -> Result<FlowStatsResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/stats/flows?top={}", instance, top)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_qos(&self, instance: &str) -> Result<QosStatsResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/stats/qos", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_groups(&self, instance: &str) -> Result<GroupStatsResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/stats/groups", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── TCP-RT ──

    pub async fn list_tcprt(&self, instance: &str, top: usize) -> Result<TcpRtResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/tcprt?top={}", instance, top)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_tcprt(&self, instance: &str) -> Result<TcpRtFlushResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/tcprt", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Drop Reason Profiler ──

    pub async fn list_drops(&self, instance: &str) -> Result<DropStatsResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/stats/drops", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_drops(&self, instance: &str) -> Result<DropFlushResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/stats/drops", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Packet Trace ──

    pub async fn start_trace(&self, instance: &str, req: &TraceStartRequest) -> Result<MessageResponse, String> {
        let resp = self.client.post(self.url(&format!("/api/v1/{}/trace", instance)))
            .json(req)
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stop_trace(&self, instance: &str) -> Result<MessageResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/trace", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn list_trace(&self, instance: &str, top: usize) -> Result<TraceResponse, String> {
        let resp = self.client.get(self.url(&format!("/api/v1/{}/trace?top={}", instance, top)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_trace(&self, instance: &str) -> Result<TraceFlushResponse, String> {
        let resp = self.client.delete(self.url(&format!("/api/v1/{}/trace/flush", instance)))
            .send().await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Internal ──

    fn connection_error(&self, e: reqwest::Error) -> String {
        if e.is_connect() {
            "aria-agent is not running. Start it with: sudo aria-agent".to_string()
        } else {
            format!("HTTP request failed: {}", e)
        }
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T, String> {
        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("Failed to read response: {}", e))?;

        if status.is_success() {
            serde_json::from_str(&body).map_err(|e| format!("Failed to parse response: {}", e))
        } else {
            match serde_json::from_str::<ApiError>(&body) {
                Ok(api_err) => Err(api_err.error),
                Err(_) => Err(format!("HTTP {}: {}", status, body)),
            }
        }
    }
}
