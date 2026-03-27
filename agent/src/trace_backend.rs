use std::collections::{HashMap, VecDeque};
use std::mem::size_of;
use std::sync::Arc;
use std::time::Duration;

use aya::maps::{Map, MapData};
use bytes::BytesMut;
use tokio::sync::{Mutex, RwLock};
use tracing::warn;

use crate::ebpf_binary::TraceBackendKind;
use aria_core::common::{TapMapRuntime, TraceStreamEvent};
use aria_core::trace_ops::{self, TraceEventEntry};

const TRACE_CACHE_LIMIT: usize = 4096;
const TRACE_STREAM_MAP_NAME: &str = "TRACE_EVENTS";

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

pub struct TraceManager {
    backend: TraceBackendKind,
    caches: RwLock<HashMap<RuntimeTapKey, VecDeque<TraceEventEntry>>>,
    runtime_tasks: Mutex<HashMap<String, Vec<tokio::task::JoinHandle<()>>>>,
}

impl TraceManager {
    pub fn new(backend: TraceBackendKind) -> Self {
        Self {
            backend,
            caches: RwLock::new(HashMap::new()),
            runtime_tasks: Mutex::new(HashMap::new()),
        }
    }

    pub fn backend(&self) -> TraceBackendKind {
        self.backend
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
                let caches = self.caches.read().await;
                Ok(caches
                    .get(&RuntimeTapKey::new(runtime.pin_path, runtime.tap_id))
                    .map(|events| events.iter().take(limit).cloned().collect())
                    .unwrap_or_default())
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
                let mut caches = self.caches.write().await;
                let key = RuntimeTapKey::new(runtime.pin_path, runtime.tap_id);
                Ok(caches.remove(&key).map(|events| events.len() as u64).unwrap_or(0))
            }
        }
    }

    pub async fn clear_tap_cache(&self, pin_path: &str, tap_id: u32) {
        if self.backend == TraceBackendKind::LegacyMap {
            return;
        }

        let mut caches = self.caches.write().await;
        caches.remove(&RuntimeTapKey::new(pin_path, tap_id));
    }

    async fn ensure_runtime_consumer(self: &Arc<Self>, pin_path: &str) -> Result<(), String> {
        if self.backend == TraceBackendKind::LegacyMap {
            return Ok(());
        }

        let mut runtime_tasks = self.runtime_tasks.lock().await;
        if runtime_tasks.contains_key(pin_path) {
            return Ok(());
        }

        let handles = match self.backend {
            TraceBackendKind::LegacyMap => Vec::new(),
            TraceBackendKind::RingBuf => vec![self.spawn_ringbuf_consumer(pin_path.to_string())],
            TraceBackendKind::PerfEventArray => self.spawn_perf_consumers(pin_path.to_string())?,
        };

        runtime_tasks.insert(pin_path.to_string(), handles);
        Ok(())
    }

    fn spawn_ringbuf_consumer(self: &Arc<Self>, pin_path: String) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            let map_path = format!("{}/{}", pin_path, TRACE_STREAM_MAP_NAME);
            let map_data = match MapData::from_pin(&map_path) {
                Ok(map) => map,
                Err(e) => {
                    warn!(pin_path = %pin_path, error = ?e, "failed to open TRACE_EVENTS ringbuf map");
                    return;
                }
            };

            let mut map = Map::RingBuf(map_data);
            let mut ring = match aya::maps::RingBuf::try_from(&mut map) {
                Ok(ring) => ring,
                Err(e) => {
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
        let entry = trace_ops::trace_event_entry_from_stream(event);
        let mut caches = self.caches.write().await;
        let events = caches
            .entry(RuntimeTapKey::new(pin_path, event.tap_id))
            .or_default();
        events.push_front(entry);
        events.truncate(TRACE_CACHE_LIMIT);
    }
}

fn decode_trace_stream_event(bytes: &[u8]) -> Option<TraceStreamEvent> {
    if bytes.len() < size_of::<TraceStreamEvent>() {
        return None;
    }

    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<TraceStreamEvent>()) })
}
