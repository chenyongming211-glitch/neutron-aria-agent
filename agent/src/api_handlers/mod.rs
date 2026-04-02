pub(crate) mod chains;
mod common;
pub(crate) mod config;
pub(crate) mod conntrack;
pub(crate) mod drops;
pub(crate) mod groups;
pub(crate) mod health;
mod metrics;
pub(crate) mod mirror;
pub(crate) mod policies;
pub(crate) mod qos;
pub(crate) mod ssl;
pub(crate) mod stats;
pub(crate) mod system;
pub(crate) mod tcprt;
pub(crate) mod trace;

use serde::Deserialize;

pub use self::chains::{create_chain, delete_chain, get_chain, list_chains};
pub use self::config::{get_config, update_config};
pub use self::conntrack::{flush_conntrack, list_conntrack};
pub use self::drops::{flush_drops, flush_kernel_drops, list_drops, list_kernel_drops};
pub use self::groups::{add_group, delete_group, list_groups, list_groups_with_stats};
pub use self::health::health;
pub use self::metrics::metrics;
pub use self::mirror::{
    add_mirror, delete_mirror, list_mirror, list_mirror_with_stats, stats_mirror,
};
pub use self::policies::{
    add_policy, batch_add_policies, delete_policy, list_policies, list_policies_with_stats,
};
pub use self::qos::{add_qos, delete_qos, list_qos, list_qos_with_stats};
pub use self::ssl::{
    flush_ssl, flush_ssl_errors, flush_ssl_global, flush_ssl_http, flush_ssl_http_global,
    get_ssl_config, list_ssl, list_ssl_errors, list_ssl_global, list_ssl_http,
    list_ssl_http_global, update_ssl_config,
};
pub use self::stats::{stats_flows, stats_groups, stats_overview, stats_qos, stats_rules};
pub use self::system::{list_instances, system_start, system_stop};
pub use self::tcprt::{
    batch_query_tcprt, filter_tcprt, flush_tcprt, list_tcprt, tcprt_histogram, tcprt_states,
};
pub use self::trace::{flush_trace, list_trace, start_trace, stop_trace};

#[derive(Deserialize)]
pub struct TopQuery {
    #[serde(default = "default_top")]
    pub top: usize,
}

fn default_top() -> usize {
    20
}
