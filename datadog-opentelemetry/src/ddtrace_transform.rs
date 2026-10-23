// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! This module contains trace mapping from otel to datadog
//! specific to datadog-opentelemetry

use crate::{
    core::sampling,
    mappings::{
        meta_get, meta_insert, metric_contains, metric_insert, otel_span_to_dd_span_into,
        CachedConfig, CowStr, DdAttributeValue, DdSpan, DdTraceChunk, SdkSpan, SpanStr,
        DEFAULT_OTLP_SERVICE_NAME, VERSION_KEY,
    },
};
use bumpalo::Bump;
use libdd_trace_utils::span::{v1::span_pool::SpanPoolV1, SpanText};
use opentelemetry::Key;
use opentelemetry_sdk::{trace::SpanData, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

static SERVICE_NAME_KEY: Key = Key::from_static_str(SERVICE_NAME);

const SAMPLING_PRIORITY_KEY: &str = "_sampling_priority_v1";
const ORIGIN_KEY: &str = "_dd.origin";
const DECISION_MAKER_KEY: &str = "_dd.p.dm";
/// The upper 64 bits of the trace id are carried by the chunk `trace_id` in v1.
const TRACE_ID_HIGH_KEY: &str = "_dd.p.tid";

/// The OTLP receiver in the agent only receives sampled spans
/// because others are dropped in the process. In this spirit, we check for the sampling
/// decision taken by the datadog sampler, and if it is missing assign AUTO_KEEP/AUTO_DROP
/// based on the otel sampling decision.
fn otel_sampling_to_dd_sampling(
    otel_trace_flags: opentelemetry::trace::TraceFlags,
    dd_span: &mut DdSpan,
) {
    if !metric_contains(dd_span, SAMPLING_PRIORITY_KEY) {
        let priority = if otel_trace_flags.is_sampled() {
            sampling::priority::AUTO_KEEP.into_i8() as f64
        } else {
            sampling::priority::AUTO_REJECT.into_i8() as f64
        };
        metric_insert(
            dd_span,
            SpanStr::from_static_str(SAMPLING_PRIORITY_KEY),
            priority,
        );
    }
}

/// Pool recycling the allocations of exported spans across exports.
pub type DdTracePool = SpanPoolV1<CowStr<'static>>;

/// Shortens the text lifetime of a [`DdTracePool`] to the lifetime of the spans of one export.
///
/// The pool is `'static` since it outlives every export, while the spans of an export borrow from
/// the `SpanData`, `Resource` and arena of that export.
pub fn trace_pool_for<'a>(pool: &'a DdTracePool) -> &'a SpanPoolV1<CowStr<'a>> {
    // SAFETY: `SpanPoolV1` resets every span (all text fields set back to the empty `'static`
    // default, collections cleared) before storing it, both in its queue and in its thread-local
    // caches, and drops the chunk shells instead of storing them. Spans and chunks handed back to
    // the pool thus never keep a `CowStr<'a>` borrowing data past the call returning them, and the
    // pool only ever stores values that are valid for `'static`. Both types only differ by the
    // lifetime of `CowStr`, so they have the same layout.
    //
    // This invariant is tested by `tests_trace_pool_recycling_frees_text_data`.
    unsafe { &*std::ptr::from_ref(pool).cast::<SpanPoolV1<CowStr<'a>>>() }
}

// Transform a vector of opentelemetry span data into a datadog v1 trace chunk
//
// When `pool` is set, the chunk and its spans are taken from it to reuse their allocations.
pub fn otel_trace_chunk_to_dd_trace_chunk<'a, I>(
    cached_config: &'a CachedConfig,
    span_data: I,
    otel_resource: &'a Resource,
    alloc: &'a Bump,
    pool: Option<&SpanPoolV1<CowStr<'a>>>,
) -> DdTraceChunk<'a>
where
    I: IntoIterator<Item = &'a SpanData>,
{
    let mut chunk = pool.map_or_else(DdTraceChunk::default, SpanPoolV1::get_chunk);
    let mut trace_id = [0; 16];
    // TODO: This can maybe faster by sorting the span_data by trace_id
    // and then handing off groups of span data?
    chunk.spans.extend(span_data.into_iter().map(|s| {
        trace_id = s.span_context.trace_id().to_bytes();
        let trace_flags = s.span_context.trace_flags();
        let sdk_span = SdkSpan::from_sdk_span_data(s);
        let dd_span = pool.map_or_else(DdSpan::default, SpanPoolV1::get_span);
        let mut dd_span = otel_span_to_dd_span_into(dd_span, &sdk_span, otel_resource, alloc);
        otel_sampling_to_dd_sampling(trace_flags, &mut dd_span);

        add_config_metadata(&mut dd_span, cached_config, otel_resource);

        dd_span
    }));
    chunk.trace_id = trace_id;

    if let Some(root) = local_root(&chunk.spans) {
        chunk.priority = match root.attributes.get(SAMPLING_PRIORITY_KEY) {
            Some(DdAttributeValue::Float(p)) => Some(*p as i32),
            _ => None,
        };
        chunk.origin = meta_get(root, ORIGIN_KEY).cloned().unwrap_or_default();
        chunk.sampling_mechanism = meta_get(root, DECISION_MAKER_KEY)
            .and_then(|dm| dm.as_str().parse::<i32>().ok())
            .map(i32::unsigned_abs);
    }
    for span in &mut chunk.spans {
        span.attributes.remove_slow(TRACE_ID_HIGH_KEY);
    }
    chunk
}

/// Returns the local root of the chunk: the span whose parent is not part of the chunk. Falls back
/// to the first span.
///
/// Sampling priority, origin and decision maker are set on every span by the span processor, so
/// any span is a valid source for the chunk-level fields; the local root is preferred for
/// consistency with libdatadog's v0.4 -> v1 conversion.
fn local_root<'s, 'a>(spans: &'s [DdSpan<'a>]) -> Option<&'s DdSpan<'a>> {
    spans
        .iter()
        .find(|s| s.parent_id == 0 || !spans.iter().any(|p| p.span_id == s.parent_id))
        .or_else(|| spans.first())
}

fn add_config_metadata<'a>(
    dd_span: &mut DdSpan<'a>,
    cached_config: &'a CachedConfig,
    otel_resource: &'a Resource,
) {
    meta_insert(
        dd_span,
        SpanStr::from_static_str("telemetry.sdk.name"),
        SpanStr::from_static_str("datadog"),
    );
    meta_insert(
        dd_span,
        SpanStr::from_static_str("telemetry.sdk.version"),
        SpanStr::from_str(&cached_config.tracer_version),
    );

    if dd_span.service.as_str() == DEFAULT_OTLP_SERVICE_NAME {
        dd_span.service = SpanStr::from_str(&cached_config.service);
    }

    for (key, value) in &cached_config.global_tags {
        meta_insert(dd_span, SpanStr::from_str(key), SpanStr::from_str(value));
    }

    if let Some(version) = &cached_config.version {
        if let Some(service_name) = otel_resource.get(&SERVICE_NAME_KEY) {
            if dd_span.service.as_str() == service_name.as_str() {
                meta_insert(
                    dd_span,
                    SpanStr::from_static_str(VERSION_KEY),
                    SpanStr::from_str(version),
                );
            }
        }
    }
}

/// Entry points into the span conversion used by benchmarks.
#[cfg(feature = "test-utils")]
#[allow(missing_docs)]
pub mod bench_support {
    use opentelemetry_sdk::{trace::SpanData, Resource};

    pub use super::DdTracePool;
    use super::{otel_trace_chunk_to_dd_trace_chunk, trace_pool_for, Bump};
    use crate::{configuration::Config, mappings::CachedConfig};

    /// What happens to the converted chunks once exported.
    #[derive(Clone, Copy, Debug)]
    pub enum Recycling {
        /// No pool: chunks and spans are allocated and dropped.
        None,
        /// Chunks and spans come from the pool and are returned to it.
        Returned,
        /// Chunks and spans come from the pool but are consumed rather than returned to it.
        Consumed,
    }

    pub struct ChunkConverter {
        cached_config: CachedConfig,
    }

    impl ChunkConverter {
        pub fn new(config: &Config) -> Self {
            Self {
                cached_config: CachedConfig::new(config),
            }
        }

        /// Converts `chunks` the way the span exporter does, then drops them according to
        /// `recycling`. Returns the number of converted spans.
        pub fn convert(
            &self,
            chunks: &[Vec<SpanData>],
            resource: &Resource,
            pool: &DdTracePool,
            recycling: Recycling,
        ) -> usize {
            let alloc = Bump::new();
            let pool = trace_pool_for(pool);
            let pool_to_use = match recycling {
                Recycling::None => None,
                Recycling::Returned | Recycling::Consumed => Some(pool),
            };
            let dd_chunks: Vec<_> = chunks
                .iter()
                .map(|c| {
                    otel_trace_chunk_to_dd_trace_chunk(
                        &self.cached_config,
                        c,
                        resource,
                        &alloc,
                        pool_to_use,
                    )
                })
                .collect();
            let span_count = dd_chunks.iter().map(|c| c.spans.len()).sum();
            match recycling {
                Recycling::Returned => drop(pool.wrap_chunks(dd_chunks)),
                Recycling::None | Recycling::Consumed => drop(dd_chunks),
            }
            span_count
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use opentelemetry::{
        trace::{SpanContext, SpanId, TraceFlags, TraceId},
        KeyValue,
    };
    use opentelemetry_sdk::{
        trace::{SpanData, SpanEvents, SpanLinks},
        Resource,
    };

    use super::{otel_trace_chunk_to_dd_trace_chunk, Bump};
    use crate::{configuration::Config, mappings::CachedConfig};

    const TRACE_ID: [u8; 16] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22,
    ];

    fn span_data(span_id: u8, parent_id: u8, attributes: Vec<KeyValue>) -> SpanData {
        SpanData {
            span_context: SpanContext::new(
                TraceId::from_bytes(TRACE_ID),
                SpanId::from_bytes([span_id; 8]),
                TraceFlags::SAMPLED,
                false,
                Default::default(),
            ),
            parent_span_id: if parent_id == 0 {
                SpanId::INVALID
            } else {
                SpanId::from_bytes([parent_id; 8])
            },
            span_kind: opentelemetry::trace::SpanKind::Internal,
            name: Cow::Borrowed("test_span"),
            start_time: std::time::SystemTime::now(),
            end_time: std::time::SystemTime::now(),
            attributes,
            dropped_attributes_count: 0,
            events: SpanEvents::default(),
            links: SpanLinks::default(),
            status: opentelemetry::trace::Status::Unset,
            instrumentation_scope: Default::default(),
            parent_span_is_remote: false,
        }
    }

    #[test]
    fn chunk_level_fields_come_from_local_root() {
        let cached_config = CachedConfig::new(&Config::builder().build());
        let resource = Resource::builder_empty().build();
        let spans = [
            span_data(2, 1, vec![KeyValue::new("_sampling_priority_v1", 1)]),
            span_data(
                1,
                0,
                vec![
                    KeyValue::new("_sampling_priority_v1", 2),
                    KeyValue::new("_dd.origin", "synthetics"),
                    KeyValue::new("_dd.p.dm", "-4"),
                    KeyValue::new("_dd.p.tid", "1111111111111111"),
                ],
            ),
        ];

        let alloc = Bump::new();
        let chunk =
            otel_trace_chunk_to_dd_trace_chunk(&cached_config, &spans, &resource, &alloc, None);

        assert_eq!(chunk.trace_id, TRACE_ID);
        assert_eq!(chunk.priority, Some(2));
        assert_eq!(chunk.origin.as_str(), "synthetics");
        assert_eq!(chunk.sampling_mechanism, Some(4));
        assert_eq!(chunk.spans.len(), 2);
        assert!(chunk
            .spans
            .iter()
            .all(|s| !s.attributes.contains_key("_dd.p.tid")));
    }

    #[test]
    fn chunk_priority_defaults_to_otel_sampling_decision() {
        let cached_config = CachedConfig::new(&Config::builder().build());
        let resource = Resource::builder_empty().build();
        let spans = [span_data(1, 0, vec![])];

        let alloc = Bump::new();
        let chunk =
            otel_trace_chunk_to_dd_trace_chunk(&cached_config, &spans, &resource, &alloc, None);

        assert_eq!(chunk.priority, Some(1));
        assert_eq!(chunk.origin.as_str(), "");
        assert_eq!(chunk.sampling_mechanism, None);
    }
}

#[cfg(test)]
/// Verifies the invariant [`trace_pool_for`] relies on: text data never survives a span or a chunk
/// being returned to a [`SpanPoolV1`].
///
/// The test uses a text type counting how many owned strings are alive. After filling every text
/// field of a chunk and of its span and returning the chunk to the pool, it checks that
/// 1. the span went back to the pool (chunk shells are dropped, only their spans are recycled)
/// 2. all of the string data has been freed
///
/// Spans, chunks, links and events are filled through pattern destructuring, so that a field added
/// to one of them fails to compile here rather than being silently left untested.
mod tests_trace_pool_recycling_frees_text_data {
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use libdd_trace_utils::span::{
        v1::{AttributeValue, Span, SpanEvent, SpanLink, ThinVec, TraceChunk},
        vec_map::VecMap,
        SpanText, TraceData,
    };

    use libdd_trace_model::{TraceText, ValueTypes};

    use super::SpanPoolV1;

    static LIVE_OWNED_STRINGS: AtomicUsize = AtomicUsize::new(0);

    fn live_owned_strings() -> usize {
        LIVE_OWNED_STRINGS.load(Ordering::SeqCst)
    }

    #[derive(Debug, Eq, PartialEq, Hash)]
    struct CountingStr(Cow<'static, str>);

    impl Default for CountingStr {
        fn default() -> Self {
            Self(Cow::Borrowed(""))
        }
    }

    impl Clone for CountingStr {
        fn clone(&self) -> Self {
            if matches!(self.0, Cow::Owned(_)) {
                LIVE_OWNED_STRINGS.fetch_add(1, Ordering::SeqCst);
            }
            Self(self.0.clone())
        }
    }

    impl Drop for CountingStr {
        fn drop(&mut self) {
            if matches!(self.0, Cow::Owned(_)) {
                LIVE_OWNED_STRINGS.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    impl std::borrow::Borrow<str> for CountingStr {
        fn borrow(&self) -> &str {
            self.0.as_ref()
        }
    }

    impl serde::Serialize for CountingStr {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(self.0.as_ref())
        }
    }

    impl SpanText for CountingStr {
        fn from_static_str(value: &'static str) -> Self {
            Self(Cow::Borrowed(value))
        }

        fn from_owned(value: String) -> Self {
            LIVE_OWNED_STRINGS.fetch_add(1, Ordering::SeqCst);
            Self(Cow::Owned(value))
        }
    }

    impl From<String> for CountingStr {
        fn from(value: String) -> Self {
            Self::from_owned(value)
        }
    }

    impl TraceText for CountingStr {
        fn from_static(value: &'static str) -> Self {
            Self(Cow::Borrowed(value))
        }
    }

    impl ValueTypes for CountingStr {
        type Text = CountingStr;
        type Bytes = &'static [u8];
        type Array = Vec<AttributeValue<Self>>;
        type Map = VecMap<CountingStr, AttributeValue<Self>>;
    }

    impl TraceData for CountingStr {}

    fn owned(s: &str) -> CountingStr {
        CountingStr::from_owned(s.to_owned())
    }

    /// Attributes holding owned text in every kind of value that can contain text.
    fn owned_attributes(prefix: &str) -> VecMap<CountingStr, AttributeValue<CountingStr>> {
        VecMap::from_iter([
            (
                owned(&format!("{prefix}.string")),
                AttributeValue::String(owned("value")),
            ),
            (
                owned(&format!("{prefix}.list")),
                AttributeValue::Array(vec![AttributeValue::String(owned("item"))]),
            ),
            (
                owned(&format!("{prefix}.kv")),
                AttributeValue::KeyValueList(VecMap::from_iter([(
                    owned("nested.key"),
                    AttributeValue::String(owned("nested.value")),
                )])),
            ),
            (
                owned(&format!("{prefix}.bytes")),
                AttributeValue::Bytes(b"bytes".as_slice()),
            ),
        ])
    }

    fn fill_span_with_owned_strings(span: &mut Span<CountingStr>) {
        let Span {
            service,
            name,
            resource,
            r#type,
            span_id: _,
            parent_id: _,
            start: _,
            duration: _,
            error: _,
            span_kind: _,
            env,
            version,
            component,
            attributes,
            span_links,
            span_events,
        } = span;
        *service = owned("my-service");
        *name = owned("my-operation");
        *resource = owned("GET /resource");
        *r#type = owned("web");
        *env = owned("prod");
        *version = owned("1.2.3");
        *component = owned("http");
        *attributes = owned_attributes("span");
        *span_links = ThinVec::from_iter([SpanLink {
            trace_id: [1; 16],
            span_id: 1,
            attributes: owned_attributes("link"),
            tracestate: owned("tracestate"),
            flags: 0,
        }]);
        *span_events = ThinVec::from_iter([SpanEvent {
            time_unix_nano: 1,
            name: owned("event.name"),
            attributes: owned_attributes("event"),
        }]);
    }

    fn fill_chunk_with_owned_strings(chunk: &mut TraceChunk<CountingStr>, span: Span<CountingStr>) {
        let TraceChunk {
            trace_id: _,
            priority: _,
            origin,
            sampling_mechanism: _,
            dropped_trace: _,
            attributes,
            spans,
        } = chunk;
        *origin = owned("synthetics");
        *attributes = owned_attributes("chunk");
        spans.push(span);
    }

    #[test]
    fn owned_strings_are_released_when_chunks_are_returned_to_the_pool() {
        let pool = SpanPoolV1::<CountingStr>::with_capacity(100);
        assert_eq!(live_owned_strings(), 0, "test precondition");

        // The pool's drop policy discards ~10% of returned spans, so retry until a span actually
        // makes it back into the pool.
        for _ in 0..1000 {
            let mut chunk = pool.get_chunk();
            let mut span = pool.get_span();
            fill_span_with_owned_strings(&mut span);
            fill_chunk_with_owned_strings(&mut chunk, span);
            assert!(
                live_owned_strings() > 0,
                "filling the chunk should have created owned strings"
            );

            drop(pool.wrap_chunks(vec![chunk]));

            // Whether the chunk is recycled or dropped by the pool's policy, every string added
            // to it or to its spans must have been released.
            assert_eq!(
                live_owned_strings(),
                0,
                "all strings must be released when chunks are returned to the pool"
            );
            if pool.pooled_spans() > 0 {
                return;
            }
        }
        panic!("no span was ever recycled into the pool");
    }
}
