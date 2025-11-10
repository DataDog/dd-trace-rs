// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::span_processor::ShardedTraces;
use hashbrown::{hash_map::Entry, HashMap};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct OpenSpanInfo {
    pub span_id: u64,
    pub name: String,
    pub start_ts: Instant,
}

#[derive(Debug)]
struct TraceInfo {
    name: String,
    start_ts: Instant,
    open_spans: HashMap<[u8; 8], OpenSpanInfo>,
}

pub struct OldTrace {
    pub tid: u128,
    pub root_span_name: String,
    pub age: Duration,
    pub open_spans: usize,
    pub open_span_details: Vec<OpenSpanInfo>,
}

#[derive(Clone, Debug)]
/// This registry tracks the age and name of currently open traces
pub struct AbandonedTracesRegistry {
    shards: ShardedTraces<InnerAbandonedTracesRegistry>,
}

impl AbandonedTracesRegistry {
    pub fn new() -> Self {
        Self {
            shards: ShardedTraces::new(|_| InnerAbandonedTracesRegistry {
                traces: HashMap::new(),
            }),
        }
    }
    pub fn register_local_root_span(&self, trace_id: [u8; 16], span_id: [u8; 8], name: String) {
        self.shards
            .write_shard(trace_id)
            .register_root_span(trace_id, span_id, name);
    }

    pub fn register_span(&self, trace_id: [u8; 16], span_id: [u8; 8], name: String) {
        self.shards
            .write_shard(trace_id)
            .register_span(trace_id, span_id, name);
    }

    pub fn finish_span(&self, trace_id: [u8; 16], span_id: [u8; 8]) {
        self.shards
            .write_shard(trace_id)
            .finish_span(trace_id, span_id);
    }

    pub fn iter_open_traces(&self) -> impl Iterator<Item = OldTrace> + use<'_> {
        let now = Instant::now();
        self.shards.iter().flat_map(move |shard| {
            let shard = shard
                .read()
                .expect("failed to lock the abandoned spans registry");
            let now = now;
            shard
                .traces
                .iter()
                .filter_map(|(tid, trace)| {
                    let age: Duration = now.checked_duration_since(trace.start_ts)?;
                    let open_span_details = trace.open_spans.values().cloned().collect::<Vec<_>>();
                    Some(OldTrace {
                        tid: u128::from_be_bytes(*tid),
                        root_span_name: trace.name.clone(),
                        age,
                        open_spans: trace.open_spans.len(),
                        open_span_details,
                    })
                })
                .collect::<Vec<_>>()
        })
    }

    pub fn iter_old_traces(&self, min_age: Duration) -> impl Iterator<Item = OldTrace> + use<'_> {
        let now = Instant::now();
        self.shards.iter().flat_map(move |shard| {
            let shard = shard
                .read()
                .expect("failed to lock the abandoned spans registry");
            let now = now;
            shard
                .traces
                .iter()
                .filter_map(|(tid, trace)| {
                    let age = now.checked_duration_since(trace.start_ts)?;
                    if age < min_age {
                        return None;
                    }
                    let open_span_details = trace.open_spans.values().cloned().collect::<Vec<_>>();
                    Some(OldTrace {
                        tid: u128::from_be_bytes(*tid),
                        root_span_name: trace.name.clone(),
                        age,
                        open_spans: trace.open_spans.len(),
                        open_span_details,
                    })
                })
                .collect::<Vec<_>>()
        })
    }
}

#[derive(Debug)]
struct InnerAbandonedTracesRegistry {
    traces: HashMap<[u8; 16], TraceInfo>,
}

impl InnerAbandonedTracesRegistry {
    fn register_root_span(&mut self, trace_id: [u8; 16], span_id: [u8; 8], name: String) {
        let Entry::Vacant(e) = self.traces.entry(trace_id) else {
            // If trace already exists, just register the span
            if let Some(trace) = self.traces.get_mut(&trace_id) {
                let span_info = OpenSpanInfo {
                    span_id: u64::from_be_bytes(span_id),
                    name,
                    start_ts: Instant::now(),
                };
                trace.open_spans.insert(span_id, span_info);
            }
            return;
        };
        let now = Instant::now();
        let span_info = OpenSpanInfo {
            span_id: u64::from_be_bytes(span_id),
            name: name.clone(),
            start_ts: now,
        };
        let mut open_spans = HashMap::new();
        open_spans.insert(span_id, span_info);
        e.insert(TraceInfo {
            open_spans,
            name,
            start_ts: now,
        });
    }

    fn register_span(&mut self, trace_id: [u8; 16], span_id: [u8; 8], name: String) {
        let now = Instant::now();
        let span_info = OpenSpanInfo {
            span_id: u64::from_be_bytes(span_id),
            name: name.clone(),
            start_ts: now,
        };

        self.traces
            .entry(trace_id)
            .or_insert(TraceInfo {
                open_spans: HashMap::new(),
                name: "".to_string(),
                start_ts: now,
            })
            .open_spans
            .insert(span_id, span_info);
    }

    fn finish_span(&mut self, trace_id: [u8; 16], span_id: [u8; 8]) {
        let Entry::Occupied(mut e) = self.traces.entry(trace_id) else {
            return;
        };
        let trace = e.get_mut();
        trace.open_spans.remove(&span_id);
        if trace.open_spans.is_empty() {
            e.remove();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use hashbrown::HashSet;

    use crate::abandoned_traces::AbandonedTracesRegistry;

    fn active_traces(r: &AbandonedTracesRegistry) -> usize {
        r.shards
            .iter()
            .map(|s| s.read().unwrap().traces.len())
            .sum::<usize>()
    }

    #[test]
    fn test_span_registration() {
        let registry = AbandonedTracesRegistry::new();
        let trace_id = [1; 16];
        let root_span_id = [1; 8];
        registry.register_local_root_span(trace_id, root_span_id, "root_span".to_owned());
        for i in 0..16 {
            let span_id = [i + 2; 8];
            registry.register_span(trace_id, span_id, format!("span_{}", i));
            registry.finish_span(trace_id, span_id);
        }
        assert_eq!(active_traces(&registry), 1);

        registry.finish_span(trace_id, root_span_id);

        assert_eq!(active_traces(&registry), 0);
    }

    #[test]
    fn test_abandoned_spans() {
        let registry = AbandonedTracesRegistry::new();
        for i in 1..=2 {
            let trace_id = (i as u128).to_be_bytes();
            let span_id = [i as u8; 8];
            registry.register_local_root_span(trace_id, span_id, format!("root_span_{i}"));
        }
        thread::sleep(Duration::from_millis(50));

        let trace_id = 3_u128.to_be_bytes();
        let span_id = [3_u8; 8];
        registry.register_local_root_span(trace_id, span_id, format!("root_span_{}", 3));

        let old_traces = registry
            .iter_old_traces(Duration::from_millis(10))
            .map(|t| (t.tid, t.root_span_name, t.open_spans))
            .collect::<HashSet<_>>();
        assert_eq!(active_traces(&registry), 3);
        assert_eq!(
            old_traces,
            HashSet::from_iter([
                (1, "root_span_1".to_string(), 1),
                (2, "root_span_2".to_string(), 1),
            ])
        );

        for i in 1..=2 {
            let trace_id = (i as u128).to_be_bytes();
            let span_id = [i as u8; 8];
            registry.finish_span(trace_id, span_id);
        }
        thread::sleep(Duration::from_millis(50));
        let old_traces = registry
            .iter_old_traces(Duration::from_millis(10))
            .map(|t| (t.tid, t.root_span_name, t.open_spans))
            .collect::<HashSet<_>>();
        assert_eq!(active_traces(&registry), 1);
        assert_eq!(
            old_traces,
            HashSet::from_iter([(3, "root_span_3".to_string(), 1),])
        );
    }
}
