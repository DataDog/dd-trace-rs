// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::span_processor::ShardedTraces;
use hashbrown::{hash_map::Entry, HashMap};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct TraceInfo {
    name: String,
    start_ts: Instant,
    open_spans: usize,
}

pub struct OldTrace {
    pub tid: u128,
    pub root_span_name: String,
    pub age: Duration,
    pub open_spans: usize,
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
    pub fn register_root_span_sampling(&self, trace_id: [u8; 16], name: String) {
        self.shards
            .write_shard(trace_id)
            .register_root_span_sampling(trace_id, name);
    }

    pub fn register_local_root_span(&self, trace_id: [u8; 16]) {
        self.shards
            .write_shard(trace_id)
            .register_root_span(trace_id);
    }

    pub fn register_span(&self, trace_id: [u8; 16]) {
        self.shards.write_shard(trace_id).register_span(trace_id);
    }

    pub fn finish_span(&self, trace_id: [u8; 16]) {
        self.shards.write_shard(trace_id).finish_span(trace_id);
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
                    Some(OldTrace {
                        tid: u128::from_be_bytes(*tid),
                        root_span_name: trace.name.clone(),
                        age,
                        open_spans: trace.open_spans,
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
                    Some(OldTrace {
                        tid: u128::from_be_bytes(*tid),
                        root_span_name: trace.name.clone(),
                        age,
                        open_spans: trace.open_spans,
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
    fn register_root_span_sampling(&mut self, trace_id: [u8; 16], name: String) {
        self.traces
            .entry(trace_id)
            .or_insert(TraceInfo {
                open_spans: 0,
                name,
                start_ts: Instant::now(),
            })
            .open_spans += 1;
    }

    fn register_root_span(&mut self, trace_id: [u8; 16]) {
        let Entry::Vacant(e) = self.traces.entry(trace_id) else {
            return;
        };
        e.insert(TraceInfo {
            open_spans: 1,
            name: "unknown_name".to_string(),
            start_ts: Instant::now(),
        });
    }

    fn register_span(&mut self, trace_id: [u8; 16]) {
        self.traces
            .entry(trace_id)
            .or_insert(TraceInfo {
                open_spans: 0,
                name: "".to_string(),
                start_ts: Instant::now(),
            })
            .open_spans += 1;
    }

    fn finish_span(&mut self, trace_id: [u8; 16]) {
        let Entry::Occupied(mut e) = self.traces.entry(trace_id) else {
            return;
        };
        let trace = e.get_mut();
        trace.open_spans -= 1;
        if trace.open_spans == 0 {
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
        registry.register_root_span_sampling(trace_id, "root_span".to_owned());
        registry.register_local_root_span(trace_id);
        for _ in 0..16 {
            registry.register_span(trace_id);
            registry.finish_span(trace_id);
        }
        assert_eq!(active_traces(&registry), 1);

        registry.finish_span(trace_id);

        assert_eq!(active_traces(&registry), 0);
    }

    #[test]
    fn test_abandoned_spans() {
        let registry = AbandonedTracesRegistry::new();
        for i in 1..=2 {
            let trace_id = (i as u128).to_be_bytes();
            registry.register_root_span_sampling(trace_id, format!("root_span_{i}"));
            registry.register_local_root_span(trace_id);
        }
        thread::sleep(Duration::from_millis(50));

        let trace_id = 3_u128.to_be_bytes();
        registry.register_root_span_sampling(trace_id, format!("root_span_{}", 3));
        registry.register_local_root_span(trace_id);

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
            registry.finish_span(trace_id);
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
