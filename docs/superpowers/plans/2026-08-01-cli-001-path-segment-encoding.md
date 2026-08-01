# REVIEW-CLI-001 Rust Client Path-Segment Encoding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every Rust-client instance, group, and service-chain name occupy exactly one HTTP path segment without changing the server API or rejecting existing names.

**Architecture:** Keep the current `ApiClient` request methods and add three private concrete URL boundaries: instance resource, group resource, and chain resource. Encode only dynamic UTF-8 values, keep static route suffixes literal, and attach numeric query parameters through `RequestBuilder::query`.

**Tech Stack:** Rust 2021, `reqwest` 0.12, `percent-encoding` 2.x, Tokio TCP test listener, GitHub Actions.

## Global Constraints

- Work directly on the sole delivery branch `v0.9-neutron-agent`; create no branch, worktree, or PR.
- Do not run local Cargo commands. Hosted GitHub Actions provides Rust compilation and behavior evidence.
- Preserve server routes, validation, JSON schemas, persistence, and ordinary client error semantics.
- Add no Python source-shape checker; CI may only select the named Rust behavior tests.
- Keep empty-name and dot-segment product policy outside `REVIEW-CLI-001`.
- Do not modify eBPF, Neutron APIs, or unrelated backlog items.

## File Map

- `user/src/api_client.rs`: real HTTP request-line RED tests, dynamic-segment encoder, three concrete URL helpers, and migration of all dynamic callers.
- `Cargo.toml`: declare the already-present `percent-encoding` crate as a workspace dependency.
- `user/Cargo.toml`: make `percent-encoding` a direct `ariactl` dependency.
- `Cargo.lock`: add `percent-encoding` to the existing `ariactl` package dependency list; no new package is introduced.
- `ci/check_neutron_stage1.py`: run the named `ariactl` URL behavior tests in hosted `rust-behavior`.
- `docs/superpowers/specs/2026-08-01-cli-001-path-segment-encoding-design.md`: record RED/GREEN evidence and final status.
- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: update both CLI-001 summaries only after exact-head GREEN.

---

### Task 1: Prove the Current Request-Target Corruption

**Files:**

- Modify: `user/src/api_client.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**

- Consumes: public `ApiClient::delete_group`, `stats_flows`, `get_chain`, and `delete_chain` methods.
- Produces: named `api_client_path_segment_` behavior tests that observe the real HTTP request line without requiring the production helper shape.

- [x] **Step 1: Add a bounded real-request capture helper**

Append a test module to `user/src/api_client.rs`. It must use Tokio's real TCP
listener and I/O types already enabled by the workspace dependency:

```rust
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
}
```

The two-second bound makes malformed-URL failures deterministic instead of
hanging the hosted test job.

- [x] **Step 2: Add group and query RED behaviors**

Inside the module add:

```rust
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
```

- [x] **Step 3: Add service-chain and literal-percent RED behaviors**

Add one test covering both chain operations:

```rust
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
```

- [x] **Step 4: Wire only the behavior-test selector**

Add this entry to `RUST_TESTS` in `ci/check_neutron_stage1.py`:

```python
["test", "--locked", "-p", "ariactl", "api_client_path_segment_"],
```

Do not inspect `api_client.rs` text or helper names from Python.

- [x] **Step 5: Run non-compiling hygiene and commit RED**

Run:

```bash
git diff --check
python3 -m py_compile ci/check_neutron_stage1.py
python3 ci/check_neutron_stage1.py --fast-contracts
git status --short
```

Expected: hygiene and existing fast contracts pass. Do not run Cargo.

Commit and push:

```bash
git add user/src/api_client.rs ci/check_neutron_stage1.py
git commit -m "test: expose Rust client path ambiguity"
git push origin v0.9-neutron-agent
```

Expected hosted result: `rust-behavior` runs the three named `ariactl` tests and
fails on their request-line assertions; `rust-build`, `fast-contracts`, and
`neutron-db-contracts` remain green. Record the exact commit and Build before
changing production code.

---

### Task 2: Encode Every Dynamic Client Path Segment

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `user/Cargo.toml`
- Modify: `user/src/api_client.rs`

**Interfaces:**

- Consumes: Task 1 request-line behaviors.
- Produces: private `encode_path_segment`, `ApiClient::instance_url`, `ApiClient::group_url`, and `ApiClient::chain_url` boundaries used by all 37 dynamic request sites.

- [x] **Step 1: Declare the existing encoding dependency directly**

Add to `[workspace.dependencies]` in `Cargo.toml`:

```toml
percent-encoding = "2"
```

Add to `[dependencies]` in `user/Cargo.toml`:

```toml
percent-encoding.workspace = true
```

In the existing `ariactl` entry in `Cargo.lock`, add the already locked package:

```toml
dependencies = [
 "aria-api",
 "clap",
 "percent-encoding",
 "reqwest",
```

Do not change any package version or checksum.

- [x] **Step 2: Add concrete encoding boundaries**

At the top of `user/src/api_client.rs` import:

```rust
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
```

Add the encoder above `ApiClient`:

```rust
fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}
```

Add these methods next to the existing `url` helper:

```rust
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
```

The static-lifetime suffix prevents callers from manufacturing route text
from request data.

- [x] **Step 3: Migrate instance and group request sites**

Replace each instance-interpolated call with its exact static suffix. Examples:

```rust
self.url(&format!("/api/v1/{}/groups", instance))
// becomes
self.instance_url(instance, "/groups")

self.url(&format!("/api/v1/{}/policies/batch", instance))
// becomes
self.instance_url(instance, "/policies/batch")

self.url(&format!("/api/v1/{}/trace/flush", instance))
// becomes
self.instance_url(instance, "/trace/flush")

self.url(&format!("/api/v1/{}/groups/{}", instance, name))
// becomes
self.group_url(instance, name)
```

Apply the same mapping to groups, policies, QoS, mirror, conntrack, config,
statistics, TCP-RT, and trace. Do not change global SSL or kernel-drop paths.

- [x] **Step 4: Separate numeric query parameters**

Convert the three instance-scoped query callers:

```rust
self.client
    .get(self.instance_url(instance, "/stats/flows"))
    .query(&[("top", top)])

self.client
    .get(self.instance_url(instance, "/tcprt"))
    .query(&[("top", top)])

self.client
    .get(self.instance_url(instance, "/trace"))
    .query(&[("top", top)])
```

Keep the existing response and error path unchanged after `.query(...)`.

- [x] **Step 5: Migrate both chain callers**

Change `get_chain` and `delete_chain` to pass `self.chain_url(name)` to
`reqwest`. Chain list and create remain on their static paths.

- [x] **Step 6: Prove every dynamic raw interpolation is gone**

Run only non-compiling checks:

```bash
git diff --check
python3 -m py_compile ci/check_neutron_stage1.py
python3 ci/check_neutron_stage1.py --fast-contracts
rg -n 'self\.url\(&format!\("/api/v1/.*(?:instance|name)' user/src/api_client.rs
git diff --stat
```

Expected: `rg` returns no dynamic instance/group/chain URL construction. The
two safe global `top` query format calls may remain. Do not run Cargo.

- [x] **Step 7: Commit, push, and require exact-head GREEN**

Commit and push:

```bash
git add Cargo.toml Cargo.lock user/Cargo.toml user/src/api_client.rs
git commit -m "fix: encode Rust client path segments"
git push origin v0.9-neutron-agent
```

Require the exact commit Build to show:

- `rust-behavior`: all `api_client_path_segment_` tests pass;
- `rust-build`: warning-denied userspace, agent, and eBPF builds pass;
- `fast-contracts`: success; and
- `neutron-db-contracts`: success.

If CI fails, inspect the exact job log and make only the smallest correction
inside the approved files. Do not weaken an assertion or hide a warning.

---

### Task 3: Review Volume and Close CLI-001

**Files:**

- Modify: `docs/superpowers/specs/2026-08-01-cli-001-path-segment-encoding-design.md`
- Modify: `docs/superpowers/plans/2026-08-01-cli-001-path-segment-encoding.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**

- Consumes: exact RED and GREEN commit/Build IDs.
- Produces: accurate fixed status and final clean/synchronized branch evidence.

- [x] **Step 1: Review scope and code volume**

Run:

```bash
git diff --stat af325e1..HEAD
git diff --numstat af325e1..HEAD
git log --oneline --stat af325e1..HEAD
git diff --check af325e1..HEAD
```

Confirm the production change is limited to the client and dependency metadata,
tests dominate any net addition, and the checker change is exactly one behavior
filter entry.

- [x] **Step 2: Record durable evidence**

Update the design status and evidence with the exact RED and GREEN commits and
Build URLs. Check off completed plan steps.

Replace both `REVIEW-CLI-001` backlog summaries with the revalidated scope:

```text
The live defect covered 37 dynamic Rust-client request sites. All instance,
group, and chain names now pass through concrete segment-encoding boundaries;
query parameters remain separate and literal percent text is encoded once.
```

Mark fixed only after exact-head GREEN. Do not close `REVIEW-DOC-022` or advance
other API/client items in this batch.

- [ ] **Step 3: Commit, push, and verify the final documentation head**

Run fast, non-compiling verification, then commit:

```bash
git diff --check
python3 ci/check_neutron_stage1.py --fast-contracts
git add docs/superpowers/specs/2026-08-01-cli-001-path-segment-encoding-design.md \
  docs/superpowers/plans/2026-08-01-cli-001-path-segment-encoding.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close Rust client path encoding"
git push origin v0.9-neutron-agent
```

Require the documentation HEAD Build to pass, then confirm:

```bash
git status --short --branch
git rev-list --left-right --count v0.9-neutron-agent...origin/v0.9-neutron-agent
```

Expected: clean worktree and `0 0` divergence.
