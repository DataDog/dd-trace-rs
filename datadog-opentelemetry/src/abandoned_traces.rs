// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::span_processor::ShardedTraces;
use hashbrown::{hash_map::Entry, HashMap};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct TraceInfo {
    open_span_names: HashMap<String, u32>,
    start_ts: Instant,
    open_spans: usize,
}

pub struct OldTrace {
    pub tid: u128,
    pub open_span_names: HashMap<String, u32>,
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

    pub fn register_span_sampling(&self, trace_id: [u8; 16], name: String) {
        self.shards
            .write_shard(trace_id)
            .register_span_sampling(trace_id, name);
    }

    pub fn register_span(&self, trace_id: [u8; 16]) {
        self.shards.write_shard(trace_id).register_span(trace_id);
    }

    pub fn finish_span(&self, trace_id: [u8; 16], name: &str) {
        self.shards
            .write_shard(trace_id)
            .finish_span(trace_id, name);
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
                        open_span_names: trace.open_span_names.clone(),
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
                        open_span_names: trace.open_span_names.clone(),
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
        self.traces.entry(trace_id).or_insert_with(|| TraceInfo {
            open_spans: 1,
            open_span_names: HashMap::from_iter([(name, 1)]),
            start_ts: Instant::now(),
        });
    }

    fn register_root_span(&mut self, trace_id: [u8; 16]) {
        let Entry::Vacant(e) = self.traces.entry(trace_id) else {
            return;
        };
        e.insert(TraceInfo {
            open_spans: 1,
            open_span_names: HashMap::new(),
            start_ts: Instant::now(),
        });
    }

    fn register_span_sampling(&mut self, trace_id: [u8; 16], name: String) {
        let c = self
            .traces
            .entry(trace_id)
            .or_insert(TraceInfo {
                open_spans: 0,
                start_ts: Instant::now(),
                open_span_names: HashMap::new(),
            })
            .open_span_names
            .entry(name)
            .or_default();
        *c += 1;
    }

    fn register_span(&mut self, trace_id: [u8; 16]) {
        self.traces
            .entry(trace_id)
            .or_insert(TraceInfo {
                open_spans: 0,
                open_span_names: HashMap::new(),
                start_ts: Instant::now(),
            })
            .open_spans += 1;
    }

    fn finish_span(&mut self, trace_id: [u8; 16], name: &str) {
        let Entry::Occupied(mut e) = self.traces.entry(trace_id) else {
            return;
        };
        let trace = e.get_mut();
        if *trace
            .open_span_names
            .entry_ref(name)
            .and_modify(|c| *c = c.saturating_sub(1))
            .or_default()
            == 0
        {
            trace.open_span_names.remove(name);
        };
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
        for i in 0..16 {
            registry.register_span(trace_id);
            registry.finish_span(trace_id, &i.to_string());
        }
        assert_eq!(active_traces(&registry), 1);

        registry.finish_span(trace_id, "root_span");

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

        let collect_old_traces = || {
            registry
                .iter_old_traces(Duration::from_millis(10))
                .map(|t| {
                    (
                        t.tid,
                        t.open_span_names
                            .iter()
                            .map(|(k, v)| (k.to_owned(), *v))
                            .collect::<Vec<_>>(),
                        t.open_spans,
                    )
                })
                .collect::<HashSet<_>>()
        };

        let old_traces = collect_old_traces();
        assert_eq!(active_traces(&registry), 3);
        assert_eq!(
            old_traces,
            HashSet::from_iter([
                (1, vec![("root_span_1".to_owned(), 1)], 1),
                (2, vec![("root_span_2".to_owned(), 1)], 1),
            ])
        );

        for i in 1..=2 {
            let trace_id = (i as u128).to_be_bytes();
            registry.finish_span(trace_id, &format!("root_span_{}", 3));
        }
        thread::sleep(Duration::from_millis(50));
        let old_traces = collect_old_traces();
        assert_eq!(active_traces(&registry), 1);
        assert_eq!(
            old_traces,
            HashSet::from_iter([(3, vec![("root_span_3".to_owned(), 1)], 1),])
        );
    }
}
