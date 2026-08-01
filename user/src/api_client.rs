use aria_api::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

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

    fn instance_url(&self, instance: &str, suffix: &'static str) -> String {
        debug_assert!(suffix.is_empty() || suffix.starts_with('/'));
        format!(
            "{}/api/v1/{}{}",
            self.base_url,
            encode_path_segment(instance),
            suffix
        )
    }

    fn group_url(&self, instance: &str, name: &str) -> String {
        format!(
            "{}/groups/{}",
            self.instance_url(instance, ""),
            encode_path_segment(name)
        )
    }

    fn chain_url(&self, name: &str) -> String {
        format!(
            "{}/api/v1/chains/{}",
            self.base_url,
            encode_path_segment(name)
        )
    }

    // ── Health ──

    pub async fn health(&self) -> Result<HealthResponse, String> {
        let resp = self
            .client
            .get(self.url("/api/v1/health"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Instances ──

    pub async fn list_instances(&self) -> Result<InstancesResponse, String> {
        let resp = self
            .client
            .get(self.url("/api/v1/instances"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── System ──

    pub async fn system_start(&self, req: &SystemStartRequest) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .post(self.url("/api/v1/system/start"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn system_stop(&self) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .post(self.url("/api/v1/system/stop"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Groups ──

    pub async fn list_groups(&self, instance: &str) -> Result<GroupsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/groups"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_group(
        &self,
        instance: &str,
        req: &AddGroupRequest,
    ) -> Result<AddGroupResponse, String> {
        let resp = self
            .client
            .post(self.instance_url(instance, "/groups"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_group(
        &self,
        instance: &str,
        name: &str,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .delete(self.group_url(instance, name))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn list_groups_with_stats(
        &self,
        instance: &str,
    ) -> Result<GroupsWithStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/groups/with_stats"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Policies ──

    pub async fn list_policies(&self, instance: &str) -> Result<PoliciesResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/policies"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_policy(
        &self,
        instance: &str,
        req: &AddPolicyRequest,
    ) -> Result<PolicyMutationResponse, String> {
        let resp = self
            .client
            .post(self.instance_url(instance, "/policies"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_policy(
        &self,
        instance: &str,
        req: &DeletePolicyRequest,
    ) -> Result<PolicyMutationResponse, String> {
        let resp = self
            .client
            .delete(self.instance_url(instance, "/policies"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn batch_add_policies(
        &self,
        instance: &str,
        req: &BatchAddPoliciesRequest,
    ) -> Result<BatchPoliciesResponse, String> {
        let resp = self
            .client
            .post(self.instance_url(instance, "/policies/batch"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn list_policies_with_stats(
        &self,
        instance: &str,
    ) -> Result<PoliciesWithStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/policies/with_stats"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── QoS ──

    pub async fn list_qos(&self, instance: &str) -> Result<QosListResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/qos"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_qos(
        &self,
        instance: &str,
        req: &AddQosRequest,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .post(self.instance_url(instance, "/qos"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_qos(
        &self,
        instance: &str,
        req: &DeleteQosRequest,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .delete(self.instance_url(instance, "/qos"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn list_qos_with_stats(
        &self,
        instance: &str,
    ) -> Result<QosWithStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/qos/with_stats"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Mirror ──

    pub async fn list_mirror(&self, instance: &str) -> Result<MirrorListResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/mirror"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn add_mirror(
        &self,
        instance: &str,
        req: &AddMirrorRequest,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .post(self.instance_url(instance, "/mirror"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_mirror(
        &self,
        instance: &str,
        req: &DeleteMirrorRequest,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .delete(self.instance_url(instance, "/mirror"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_mirror(&self, instance: &str) -> Result<MirrorStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/stats/mirror"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn list_mirror_with_stats(
        &self,
        instance: &str,
    ) -> Result<MirrorWithStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/mirror/with_stats"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Conntrack ──

    pub async fn list_conntrack(&self, instance: &str) -> Result<ConntrackResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/conntrack"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_conntrack(&self, instance: &str) -> Result<ConntrackFlushResponse, String> {
        let resp = self
            .client
            .delete(self.instance_url(instance, "/conntrack"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Config ──

    pub async fn get_config(&self, instance: &str) -> Result<ConfigResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/config"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn update_config(
        &self,
        instance: &str,
        req: &UpdateConfigRequest,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .put(self.instance_url(instance, "/config"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Stats ──

    pub async fn stats_overview(&self, instance: &str) -> Result<StatsOverview, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/stats"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_rules(&self, instance: &str) -> Result<RuleStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/stats/rules"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_flows(
        &self,
        instance: &str,
        top: usize,
    ) -> Result<FlowStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/stats/flows"))
            .query(&[("top", top)])
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_qos(&self, instance: &str) -> Result<QosStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/stats/qos"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stats_groups(&self, instance: &str) -> Result<GroupStatsResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/stats/groups"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── TCP-RT ──

    pub async fn list_tcprt(&self, instance: &str, top: usize) -> Result<TcpRtResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/tcprt"))
            .query(&[("top", top)])
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_tcprt(&self, instance: &str) -> Result<TcpRtFlushResponse, String> {
        let resp = self
            .client
            .delete(self.instance_url(instance, "/tcprt"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    #[allow(dead_code)]
    pub async fn batch_query_tcprt(
        &self,
        req: &TcpRtBatchQueryRequest,
    ) -> Result<TcpRtBatchQueryResponse, String> {
        let resp = self
            .client
            .post(self.url("/api/v1/tcprt/query"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn filter_tcprt(
        &self,
        req: &TcpRtFilterRequest,
    ) -> Result<TcpRtFilterResponse, String> {
        let resp = self
            .client
            .post(self.url("/api/v1/tcprt/filter"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn tcprt_histogram(&self, instance: &str) -> Result<TcpRtHistogramResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/tcprt/histogram"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn tcprt_states(&self, instance: &str) -> Result<TcpRtStatesResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/tcprt/states"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── SSL ──

    pub async fn list_ssl(&self, _instance: &str, top: usize) -> Result<SslListResponse, String> {
        let resp = self
            .client
            .get(self.url(&format!("/api/v1/ssl?top={}", top)))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_ssl(&self, _instance: &str) -> Result<SslFlushResponse, String> {
        let resp = self
            .client
            .delete(self.url("/api/v1/ssl"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── SSL HTTP ──

    pub async fn list_ssl_http(
        &self,
        _instance: &str,
        top: usize,
    ) -> Result<SslHttpListResponse, String> {
        let resp = self
            .client
            .get(self.url(&format!("/api/v1/ssl/http?top={}", top)))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_ssl_http(&self, _instance: &str) -> Result<SslHttpFlushResponse, String> {
        let resp = self
            .client
            .delete(self.url("/api/v1/ssl/http"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Global SSL Observability Config ──
    // SSL uprobe is process-level, not tied to any network interface

    pub async fn get_ssl_config(&self) -> Result<SslGlobalConfigResponse, String> {
        let resp = self
            .client
            .get(self.url("/api/v1/ssl/config"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn update_ssl_config(&self, enabled: bool) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .put(self.url("/api/v1/ssl/config"))
            .json(&UpdateSslGlobalConfigRequest { enabled })
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── SSL Error Events ──

    pub async fn list_ssl_errors(&self) -> Result<SslErrorListResponse, String> {
        let resp = self
            .client
            .get(self.url("/api/v1/ssl/errors"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_ssl_errors(&self) -> Result<SslErrorFlushResponse, String> {
        let resp = self
            .client
            .delete(self.url("/api/v1/ssl/errors"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Service Chains ──

    pub async fn list_chains(&self) -> Result<ServiceChainListResponse, String> {
        let resp = self
            .client
            .get(self.url("/api/v1/chains"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn get_chain(&self, name: &str) -> Result<ServiceChainEntry, String> {
        let resp = self
            .client
            .get(self.chain_url(name))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn create_chain(
        &self,
        req: &CreateServiceChainRequest,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .post(self.url("/api/v1/chains"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn delete_chain(&self, name: &str) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .delete(self.chain_url(name))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Kernel Drop Observability ──

    pub async fn list_kernel_drops(
        &self,
        query: &KernelDropQuery,
    ) -> Result<KernelDropStatsResponse, String> {
        let resp = self
            .client
            .get(self.url("/api/v1/stats/kernel_drops"))
            .query(query)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_kernel_drops(
        &self,
        query: &KernelDropQuery,
    ) -> Result<KernelDropFlushResponse, String> {
        let resp = self
            .client
            .delete(self.url("/api/v1/stats/kernel_drops"))
            .query(query)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    // ── Packet Trace ──

    pub async fn start_trace(
        &self,
        instance: &str,
        req: &TraceStartRequest,
    ) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .post(self.instance_url(instance, "/trace"))
            .json(req)
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn stop_trace(&self, instance: &str) -> Result<MessageResponse, String> {
        let resp = self
            .client
            .delete(self.instance_url(instance, "/trace"))
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn list_trace(&self, instance: &str, top: usize) -> Result<TraceResponse, String> {
        let resp = self
            .client
            .get(self.instance_url(instance, "/trace"))
            .query(&[("top", top)])
            .send()
            .await
            .map_err(|e| self.connection_error(e))?;
        self.parse_response(resp).await
    }

    pub async fn flush_trace(&self, instance: &str) -> Result<TraceFlushResponse, String> {
        let resp = self
            .client
            .delete(self.instance_url(instance, "/trace/flush"))
            .send()
            .await
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

    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, String> {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    async fn capture_one_request() -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let capture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let body = r#"{"error":"expected test response"}"#;
            let response = format!(
                "HTTP/1.1 500 Internal Server Error\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_string()
        });
        (format!("http://{}", address), capture)
    }

    async fn captured_request_line(capture: JoinHandle<String>) -> String {
        tokio::time::timeout(Duration::from_secs(2), capture)
            .await
            .expect("client did not send a request")
            .expect("request capture task failed")
    }

    #[tokio::test]
    async fn api_client_path_segment_group_delete_encodes_instance_and_group() {
        let (base_url, capture) = capture_one_request().await;
        let client = ApiClient::new(&base_url);
        let _ = client
            .delete_group("tap/blue?mode#tail", "group/red?mode#tail")
            .await;

        assert_eq!(
            captured_request_line(capture).await,
            "DELETE /api/v1/tap%2Fblue%3Fmode%23tail/groups/group%2Fred%3Fmode%23tail HTTP/1.1"
        );
    }

    #[tokio::test]
    async fn api_client_path_segment_query_stays_outside_encoded_instance() {
        let (base_url, capture) = capture_one_request().await;
        let client = ApiClient::new(&base_url);
        let _ = client.stats_flows("tap/blue?mode#tail", 7).await;

        assert_eq!(
            captured_request_line(capture).await,
            "GET /api/v1/tap%2Fblue%3Fmode%23tail/stats/flows?top=7 HTTP/1.1"
        );
    }

    #[tokio::test]
    async fn api_client_path_segment_chain_get_and_delete_encode_once() {
        let (get_base_url, get_capture) = capture_one_request().await;
        let get_client = ApiClient::new(&get_base_url);
        let _ = get_client.get_chain("chain%2Fblue").await;
        assert_eq!(
            captured_request_line(get_capture).await,
            "GET /api/v1/chains/chain%252Fblue HTTP/1.1"
        );

        let (delete_base_url, delete_capture) = capture_one_request().await;
        let delete_client = ApiClient::new(&delete_base_url);
        let _ = delete_client.delete_chain("chain/red?#tail").await;
        assert_eq!(
            captured_request_line(delete_capture).await,
            "DELETE /api/v1/chains/chain%2Fred%3F%23tail HTTP/1.1"
        );
    }
}
