use std::collections::{HashMap, HashSet, VecDeque};
use std::mem::size_of;
use std::sync::Arc;
use std::time::Duration;

use aya::maps::{Map, MapData, PerCpuArray};
use bytes::BytesMut;
use tokio::sync::{Mutex, RwLock};
use tracing::warn;

use crate::ebpf_binary::TraceBackendKind;
use aria_core::common::{TapMapRuntime, TraceStreamEvent};
use aria_core::ebpf_ops::TraceMapMode;
use aria_core::trace_ops::{self, TraceEventEntry};

const TRACE_CACHE_LIMIT: usize = 4096;
const TRACE_STREAM_MAP_NAME: &str = "TRACE_EVENTS";
const TRACE_SEQ_MAP_NAME: &str = "TRACE_SEQ";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RuntimeTapKey {
    pin_path: String,
    tap_id: u32,
}

impl RuntimeTapKey {
    fn new(pin_path: &str, tap_id: u32) -> Self {
        Self {
            pin_path: pin_path.to_string(),
            tap_id,
        }
    }
}

#[derive(Clone, Debug)]
struct CachedTraceEvent {
    cpu_id: u32,
    entry: TraceEventEntry,
}

#[derive(Clone, Debug, Default)]
struct StreamTapState {
    flush_watermark: HashMap<u32, u64>,
}

#[derive(Clone, Debug, Default)]
pub struct TraceRuntimeStatusSnapshot {
    pub registered_taps: usize,
    pub lost_events: u64,
    pub cache_evictions: u64,
    pub consumer_failures: u64,
    pub consumer_restarts: u64,
    pub last_error: Option<String>,
    pub active_consumers: usize,
}

#[derive(Debug, Default)]
struct StreamRuntimeState {
    registered_taps: HashSet<u32>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    lost_events: u64,
    cache_evictions: u64,
    consumer_failures: u64,
    consumer_restarts: u64,
    last_error: Option<String>,
}

#[inline]
fn visible_after_flush_watermark(seq: u64, next_seq_watermark: Option<&u64>) -> bool {
    // TRACE_SEQ stores the next sequence number that will be assigned on each CPU.
    // After a flush, the first post-flush event on that CPU uses exactly that seq,
    // so visibility must be `>= watermark`, not `> watermark`.
    next_seq_watermark
        .map(|watermark| seq >= *watermark)
        .unwrap_or(true)
}

pub struct TraceManager {
    backend: TraceBackendKind,
    caches: RwLock<HashMap<RuntimeTapKey, VecDeque<CachedTraceEvent>>>,
    tap_states: RwLock<HashMap<RuntimeTapKey, StreamTapState>>,
    runtime_states: Mutex<HashMap<String, StreamRuntimeState>>,
}

impl TraceManager {
    pub fn new(backend: TraceBackendKind) -> Self {
        Self {
            backend,
            caches: RwLock::new(HashMap::new()),
            tap_states: RwLock::new(HashMap::new()),
            runtime_states: Mutex::new(HashMap::new()),
        }
    }

    pub fn backend(&self) -> TraceBackendKind {
        self.backend
    }

    pub fn map_mode(&self) -> TraceMapMode {
        match self.backend {
            TraceBackendKind::LegacyMap => TraceMapMode::Legacy,
            TraceBackendKind::PerfEventArray | TraceBackendKind::RingBuf => TraceMapMode::Stream,
        }
    }

    pub async fn get_trace_events(
        self: &Arc<Self>,
        runtime: TapMapRuntime<'_>,
        limit: usize,
    ) -> Result<Vec<TraceEventEntry>, String> {
        match self.backend {
            TraceBackendKind::LegacyMap => trace_ops::get_trace_events(runtime, limit),
            TraceBackendKind::PerfEventArray | TraceBackendKind::RingBuf => {
                self.ensure_runtime_consumer(runtime.pin_path).await?;
                let key = RuntimeTapKey::new(runtime.pin_path, runtime.tap_id);
                let flush_watermark = {
                    let tap_states = self.tap_states.read().await;
                    tap_states
                        .get(&key)
                        .map(|state| state.flush_watermark.clone())
                        .unwrap_or_default()
                };
                let caches = self.caches.read().await;
                let mut events: Vec<CachedTraceEvent> = caches
                    .get(&key)
                    .map(|entries| {
                        entries
                            .iter()
                            .filter(|cached| {
                                visible_after_flush_watermark(
                                    cached.entry.seq,
                                    flush_watermark.get(&cached.cpu_id),
                                )
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                events.sort_by(|a, b| {
                    b.entry
                        .timestamp
                        .cmp(&a.entry.timestamp)
                        .then_with(|| b.entry.seq.cmp(&a.entry.seq))
                        .then_with(|| b.cpu_id.cmp(&a.cpu_id))
                });
                Ok(events
                    .into_iter()
                    .take(limit)
                    .map(|cached| cached.entry)
                    .collect())
            }
        }
    }

    pub async fn flush_trace_events(
        self: &Arc<Self>,
        runtime: TapMapRuntime<'_>,
    ) -> Result<u64, String> {
        match self.backend {
            TraceBackendKind::LegacyMap => trace_ops::flush_trace_log(runtime),
            TraceBackendKind::PerfEventArray | TraceBackendKind::RingBuf => {
                let key = RuntimeTapKey::new(runtime.pin_path, runtime.tap_id);
                let flushed = {
                    let tap_states = self.tap_states.read().await;
                    let flush_watermark = tap_states
                        .get(&key)
                        .map(|state| state.flush_watermark.clone())
                        .unwrap_or_default();
                    let caches = self.caches.read().await;
                    caches
                        .get(&key)
                        .map(|events| {
                            events
                                .iter()
                                .filter(|cached| {
                                    visible_after_flush_watermark(
                                        cached.entry.seq,
                                        flush_watermark.get(&cached.cpu_id),
                                    )
                                })
                                .count() as u64
                        })
                        .unwrap_or(0)
                };
                let watermark = Self::read_trace_seq_watermark(runtime.pin_path)?;
                let mut tap_states = self.tap_states.write().await;
                tap_states.entry(key).or_default().flush_watermark = watermark;
                Ok(flushed)
            }
        }
    }

    pub async fn register_tap(self: &Arc<Self>, pin_path: &str, tap_id: u32) -> Result<(), String> {
        if self.backend == TraceBackendKind::LegacyMap {
            return Ok(());
        }

        let key = RuntimeTapKey::new(pin_path, tap_id);
        {
            let mut tap_states = self.tap_states.write().await;
            tap_states.entry(key).or_default();
        }

        {
            let mut runtime_states = self.runtime_states.lock().await;
            runtime_states
                .entry(pin_path.to_string())
                .or_default()
                .registered_taps
                .insert(tap_id);
        }

        self.ensure_runtime_consumer(pin_path).await
    }

    pub async fn unregister_tap(&self, pin_path: &str, tap_id: u32) {
        if self.backend == TraceBackendKind::LegacyMap {
            return;
        }

        let key = RuntimeTapKey::new(pin_path, tap_id);
        let mut caches = self.caches.write().await;
        caches.remove(&key);
        drop(caches);

        let mut tap_states = self.tap_states.write().await;
        tap_states.remove(&key);
        drop(tap_states);

        let mut runtime_states = self.runtime_states.lock().await;
        let mut remove_runtime = false;
        if let Some(state) = runtime_states.get_mut(pin_path) {
            state.registered_taps.remove(&tap_id);
            if state.registered_taps.is_empty() {
                Self::abort_runtime_tasks(state);
                remove_runtime = true;
            }
        }
        if remove_runtime {
            runtime_states.remove(pin_path);
        }
    }

    pub async fn clear_tap_cache(&self, pin_path: &str, tap_id: u32) {
        if self.backend == TraceBackendKind::LegacyMap {
            return;
        }

        let mut caches = self.caches.write().await;
        caches.remove(&RuntimeTapKey::new(pin_path, tap_id));
    }

    pub async fn runtime_status(&self) -> HashMap<String, TraceRuntimeStatusSnapshot> {
        let runtime_states = self.runtime_states.lock().await;
        runtime_states
            .iter()
            .map(|(pin_path, state)| {
                (
                    pin_path.clone(),
                    TraceRuntimeStatusSnapshot {
                        registered_taps: state.registered_taps.len(),
                        lost_events: state.lost_events,
                        cache_evictions: state.cache_evictions,
                        consumer_failures: state.consumer_failures,
                        consumer_restarts: state.consumer_restarts,
                        last_error: state.last_error.clone(),
                        active_consumers: state
                            .tasks
                            .iter()
                            .filter(|task| !task.is_finished())
                            .count(),
                    },
                )
            })
            .collect()
    }

    async fn ensure_runtime_consumer(self: &Arc<Self>, pin_path: &str) -> Result<(), String> {
        if self.backend == TraceBackendKind::LegacyMap {
            return Ok(());
        }

        let mut runtime_states = self.runtime_states.lock().await;
        let state = runtime_states.entry(pin_path.to_string()).or_default();
        let needs_restart =
            state.tasks.is_empty() || state.tasks.iter().any(|task| task.is_finished());
        if !needs_restart {
            return Ok(());
        }

        if !state.tasks.is_empty() {
            state.consumer_restarts += 1;
            Self::abort_runtime_tasks(state);
        }

        let handles = match self.backend {
            TraceBackendKind::LegacyMap => Vec::new(),
            TraceBackendKind::RingBuf => vec![self.spawn_ringbuf_consumer(pin_path.to_string())],
            TraceBackendKind::PerfEventArray => {
                match self.spawn_perf_consumers(pin_path.to_string()) {
                    Ok(handles) => handles,
                    Err(error) => {
                        state.consumer_failures += 1;
                        state.last_error = Some(error.clone());
                        return Err(error);
                    }
                }
            }
        };

        state.last_error = None;
        state.tasks = handles;
        Ok(())
    }

    fn abort_runtime_tasks(state: &mut StreamRuntimeState) {
        for handle in state.tasks.drain(..) {
            handle.abort();
        }
    }

    fn spawn_ringbuf_consumer(self: &Arc<Self>, pin_path: String) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            let map_path = format!("{}/{}", pin_path, TRACE_STREAM_MAP_NAME);
            let map_data = match MapData::from_pin(&map_path) {
                Ok(map) => map,
                Err(e) => {
                    manager
                        .record_consumer_failure(
                            &pin_path,
                            format!("failed to open TRACE_EVENTS ringbuf map: {:?}", e),
                        )
                        .await;
                    warn!(pin_path = %pin_path, error = ?e, "failed to open TRACE_EVENTS ringbuf map");
                    return;
                }
            };

            let mut map = Map::RingBuf(map_data);
            let mut ring = match aya::maps::RingBuf::try_from(&mut map) {
                Ok(ring) => ring,
                Err(e) => {
                    manager
                        .record_consumer_failure(
                            &pin_path,
                            format!("failed to convert TRACE_EVENTS ringbuf map: {:?}", e),
                        )
                        .await;
                    warn!(pin_path = %pin_path, error = ?e, "failed to convert TRACE_EVENTS ringbuf map");
                    return;
                }
            };

            loop {
                let mut drained = false;
                while let Some(item) = ring.next() {
                    drained = true;
                    if let Some(event) = decode_trace_stream_event(item.as_ref()) {
                        manager.push_event(&pin_path, event).await;
                    }
                }
                if !drained {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        })
    }

    fn spawn_perf_consumers(
        self: &Arc<Self>,
        pin_path: String,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, String> {
        let map_path = format!("{}/{}", pin_path, TRACE_STREAM_MAP_NAME);
        let map_data = MapData::from_pin(&map_path)
            .map_err(|e| format!("open TRACE_EVENTS perf map {}: {:?}", map_path, e))?;
        let map = Map::PerfEventArray(map_data);
        let mut perf_array = aya::maps::perf::AsyncPerfEventArray::try_from(map)
            .map_err(|e| format!("convert TRACE_EVENTS perf map {}: {:?}", map_path, e))?;

        let mut handles = Vec::new();
        for cpu in aya::util::online_cpus().map_err(|(_, e)| format!("list online CPUs: {}", e))? {
            let mut buffer = perf_array
                .open(cpu, None)
                .map_err(|e| format!("open perf buffer for cpu {}: {:?}", cpu, e))?;
            let manager = self.clone();
            let runtime_pin = pin_path.clone();
            let handle = tokio::spawn(async move {
                let mut buffers = (0..32)
                    .map(|_| BytesMut::with_capacity(size_of::<TraceStreamEvent>()))
                    .collect::<Vec<_>>();
                loop {
                    match buffer.read_events(&mut buffers).await {
                        Ok(events) => {
                            if events.lost > 0 {
                                manager
                                    .record_lost_events(&runtime_pin, events.lost as u64)
                                    .await;
                                warn!(
                                    pin_path = %runtime_pin,
                                    cpu,
                                    lost = events.lost,
                                    "lost trace perf events"
                                );
                            }
                            for buf in buffers.iter_mut().take(events.read) {
                                if let Some(event) = decode_trace_stream_event(buf.as_ref()) {
                                    manager.push_event(&runtime_pin, event).await;
                                }
                                buf.clear();
                            }
                        }
                        Err(e) => {
                            manager
                                .record_consumer_failure(
                                    &runtime_pin,
                                    format!("trace perf reader exited on cpu {}: {:?}", cpu, e),
                                )
                                .await;
                            warn!(
                                pin_path = %runtime_pin,
                                cpu,
                                error = ?e,
                                "trace perf reader exited"
                            );
                            break;
                        }
                    }
                }
            });
            handles.push(handle);
        }

        Ok(handles)
    }

    async fn push_event(&self, pin_path: &str, event: TraceStreamEvent) {
        let tap_id = event.tap_id;
        let cpu_id = event.cpu_id;
        let entry = trace_ops::trace_event_entry_from_stream(event);
        let cached = CachedTraceEvent { cpu_id, entry };
        let mut caches = self.caches.write().await;
        let events = caches
            .entry(RuntimeTapKey::new(pin_path, tap_id))
            .or_default();
        if events.len() == TRACE_CACHE_LIMIT {
            events.pop_back();
            events.push_front(cached);
            drop(caches);
            self.record_cache_eviction(pin_path).await;
            return;
        }
        events.push_front(cached);
    }

    async fn record_lost_events(&self, pin_path: &str, lost: u64) {
        let mut runtime_states = self.runtime_states.lock().await;
        if let Some(state) = runtime_states.get_mut(pin_path) {
            state.lost_events += lost;
        }
    }

    async fn record_cache_eviction(&self, pin_path: &str) {
        let mut runtime_states = self.runtime_states.lock().await;
        if let Some(state) = runtime_states.get_mut(pin_path) {
            state.cache_evictions += 1;
        }
    }

    async fn record_consumer_failure(&self, pin_path: &str, error: String) {
        let mut runtime_states = self.runtime_states.lock().await;
        if let Some(state) = runtime_states.get_mut(pin_path) {
            state.consumer_failures += 1;
            state.last_error = Some(error);
        }
    }

    fn read_trace_seq_watermark(pin_path: &str) -> Result<HashMap<u32, u64>, String> {
        let map_path = format!("{}/{}", pin_path, TRACE_SEQ_MAP_NAME);
        let map_data = MapData::from_pin(&map_path)
            .map_err(|e| format!("open TRACE_SEQ map {}: {:?}", map_path, e))?;
        let map = PerCpuArray::<MapData, u64>::try_from(Map::PerCpuArray(map_data))
            .map_err(|e| format!("convert TRACE_SEQ map {}: {:?}", map_path, e))?;
        let values = map
            .get(&0u32, 0)
            .map_err(|e| format!("read TRACE_SEQ map {}: {:?}", map_path, e))?;
        Ok(values
            .iter()
            .enumerate()
            .map(|(cpu_id, seq)| (cpu_id as u32, *seq))
            .collect())
    }
}

fn decode_trace_stream_event(bytes: &[u8]) -> Option<TraceStreamEvent> {
    if bytes.len() < size_of::<TraceStreamEvent>() {
        return None;
    }

    let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<TraceStreamEvent>()) };
    if event.is_ipv6 > 1 || event.direction > 1 {
        return None;
    }

    Some(event)
}
