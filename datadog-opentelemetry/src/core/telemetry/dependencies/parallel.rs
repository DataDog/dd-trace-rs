// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Maps items on several threads, for `build.rs` to resolve the members' trees in parallel.
//!
//! The build script compiles this file too (through `#[path]`), so it must only use `std`. The
//! tracer only compiles it for its tests.

use std::{
    panic,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};

/// Runs `f` on each of `items` on up to `threads` threads, the current one included, and returns
/// the results in the order of `items`.
pub fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let threads = threads.clamp(1, items.len().max(1));
    let next = AtomicUsize::new(0);
    let work = || {
        let mut done = Vec::new();
        loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let Some(item) = items.get(index) else {
                return done;
            };
            done.push((index, f(item)));
        }
    };
    let mut results = thread::scope(|scope| {
        // Spawning fails when threads are limited, e.g. in a container: the current thread
        // works too, so that every item is still mapped.
        let workers: Vec<_> = (1..threads)
            .filter_map(|_| thread::Builder::new().spawn_scoped(scope, work).ok())
            .collect();
        let mut results = work();
        for worker in workers {
            // A panic in `f` would have failed the sequential loop too.
            let done = worker
                .join()
                .unwrap_or_else(|panic| panic::resume_unwind(panic));
            results.extend(done);
        }
        results
    });
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::Mutex,
        time::{Duration, Instant},
    };

    use super::*;

    #[test]
    fn test_parallel_map_keeps_the_order() {
        let items: Vec<u64> = (0..20).collect();
        // The first items take the longest, so they finish last.
        let results = parallel_map(&items, 4, |&item| {
            thread::sleep(Duration::from_millis(20 - item));
            item * 10
        });
        assert_eq!(results, (0..20).map(|item| item * 10).collect::<Vec<_>>());
    }

    #[test]
    fn test_parallel_map_runs_concurrently() {
        // Each item waits for all of them to start, or for the deadline when they can't all run
        // at once, so the peak of the running items is the number of threads.
        let (started, running, peak) = (
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        parallel_map(&[(); 4], 4, |()| {
            started.fetch_add(1, Ordering::SeqCst);
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            while started.load(Ordering::SeqCst) < 4 && Instant::now() < deadline {
                thread::yield_now();
            }
            running.fetch_sub(1, Ordering::SeqCst);
        });
        assert_eq!(peak.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_parallel_map_on_the_current_thread() {
        let current = thread::current().id();
        for threads in [0, 1] {
            let ids = Mutex::new(BTreeSet::new());
            let results = parallel_map(&[1, 2, 3], threads, |&item| {
                ids.lock()
                    .expect("not poisoned")
                    .insert(format!("{:?}", thread::current().id()));
                item + 1
            });
            assert_eq!(results, vec![2, 3, 4]);
            let ids = ids.into_inner().expect("not poisoned");
            assert_eq!(ids, BTreeSet::from([format!("{current:?}")]));
        }
    }

    #[test]
    fn test_parallel_map_with_more_threads_than_items() {
        assert_eq!(parallel_map(&["a", "b"], 8, |item| item.len()), vec![1, 1]);
        assert_eq!(
            parallel_map(&[] as &[u8], 4, |&item| item),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn test_parallel_map_propagates_panics() {
        let items: Vec<usize> = (0..8).collect();
        let result = panic::catch_unwind(|| {
            parallel_map(&items, 4, |&item| {
                assert_ne!(item, 5, "item {item}");
                item
            })
        });
        let payload = result.expect_err("the panic is propagated");
        let message = payload
            .downcast_ref::<String>()
            .expect("a formatted panic message");
        assert!(message.contains("item 5"), "{message}");
    }
}
