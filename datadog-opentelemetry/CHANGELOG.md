# Changelog

## 0.6.0 (Oct 29, 2026)

- Apply tracing_enabled from APM_TRACING in https://github.com/DataDog/dd-trace-rs/pull/340
- Flatten array span attributes to key.N in https://github.com/DataDog/dd-trace-rs/pull/338
- Raise MSRV to 1.91.1 in https://github.com/DataDog/dd-trace-rs/pull/349

## 0.5.3 (Oct 26, 2026)

- Handle repeated traceparent and tracestate headers in https://github.com/DataDog/dd-trace-rs/pull/325
- Support DD_TRACE_HTTP_{SERVER,CLIENT}_ERROR_STATUSES in https://github.com/DataDog/dd-trace-rs/pull/328
- Set _dd.base_service on spans with an overridden service in https://github.com/DataDog/dd-trace-rs/pull/331
- Parse ipv6 agent host values correctly in https://github.com/DataDog/dd-trace-rs/pull/321
- Support space-separated DD_TAGS and tags without a value in https://github.com/DataDog/dd-trace-rs/pull/322
- Otel thread-level context sharing in https://github.com/DataDog/dd-trace-rs/pull/269
- Enable hostname reporting on trace exporter in https://github.com/DataDog/dd-trace-rs/pull/308
- Add stats cardinality limits configurations in https://github.com/DataDog/dd-trace-rs/pull/309
- Route the tracer's own diagnostics through tracing in https://github.com/DataDog/dd-trace-rs/pull/281
- Accept 0/1 as boolean flags in configuration in https://github.com/DataDog/dd-trace-rs/pull/305

## 0.5.2 (Aug 28, 2026)

- Preserve unchanged `ot` member order in W3C tracestate in https://github.com/DataDog/dd-trace-rs/pull/296
- Emit and forward OTel consistent-probability ot tracestate member in https://github.com/DataDog/dd-trace-rs/pull/283
- Shutdown with a deadline in https://github.com/DataDog/dd-trace-rs/pull/276
- Run remote config on the trace exporter's shared runtime in https://github.com/DataDog/dd-trace-rs/pull/275
- Drain pending spans in force_flush [APMSP-3915] in https://github.com/DataDog/dd-trace-rs/pull/287
- Emit expected rate-limiter metric `_dd.limit_psr` in https://github.com/DataDog/dd-trace-rs/pull/288

## 0.5.1 (Aug 13, 2026)

- Only error when no extractor recovers a real trace [SVLS-9550] in https://github.com/DataDog/dd-trace-rs/pull/284

## 0.5.0 (Jul 10, 2026)

- Upgrade opentelemetry to 0.32 in https://github.com/DataDog/dd-trace-rs/pull/270
- Add B3 single and multi-header trace propagation support in https://github.com/DataDog/dd-trace-rs/pull/262
- Add support for `DD_TRACE_PROPAGATION_BEHAVIOR_EXTRACT` parameter in https://github.com/DataDog/dd-trace-rs/pull/248
- Support `OTEL_PROPAGATORS` as propagation style fallback in https://github.com/DataDog/dd-trace-rs/pull/271
- Support `OTEL_SERVICE_NAME` as alias for `DD_SERVICE` in https://github.com/DataDog/dd-trace-rs/pull/266
- Add `with_view` support to `DatadogMetricsBuilder` in https://github.com/DataDog/dd-trace-rs/pull/272
- Adopt libdatadog's `TraceBuffer` in https://github.com/DataDog/dd-trace-rs/pull/226
- Propagate session IDs and process lineage to libdatadog in https://github.com/DataDog/dd-trace-rs/pull/216
- Fix baggage tags to be added to any root span in https://github.com/DataDog/dd-trace-rs/pull/265

## 0.4.0 (Jun 05, 2026)

- Add support for W3C baggage propagation in https://github.com/DataDog/dd-trace-rs/pull/200
- Expose synchronous trace writes in https://github.com/DataDog/dd-trace-rs/pull/221
- Update MSRV to Rust 1.87 in https://github.com/DataDog/dd-trace-rs/pull/232
- Add root invocation span with OTel tracing in datadog-aws-lambda in https://github.com/DataDog/dd-trace-rs/pull/213
- Use sampling from libdatadog in https://github.com/DataDog/dd-trace-rs/pull/154
- Add support for baggage span tags in https://github.com/DataDog/dd-trace-rs/pull/223
- Expose css obfuscation parameter for client-side stats in https://github.com/DataDog/dd-trace-rs/pull/225
- Accept Remote Config list-shape tags and honor tracing_sampling_rate in https://github.com/DataDog/dd-trace-rs/pull/227
- Add `https` feature to opt into the rustls TLS stack in https://github.com/DataDog/dd-trace-rs/pull/241

## 0.3.3 (May 06, 2026)

- Fix config, use DD_AGENT_HOST and DD_TRACE_AGENT_PORT to derive agent url if it is an empty string in env in https://github.com/DataDog/dd-trace-rs/pull/208
- Add publication of the tracer metadata upon global init in https://github.com/DataDog/dd-trace-rs/pull/210
- Fix sampling rate limiter, token count would not be restored if the fraction was smaller than 1 in https://github.com/DataDog/dd-trace-rs/pull/215
- Add automatic datadog agent unix socket detection in https://github.com/DataDog/dd-trace-rs/pull/204
- Limit the number of keys parsed from tracestate in https://github.com/DataDog/dd-trace-rs/pull/218

## 0.3.2 (Mar 27, 2026)

- Change telemetry.sdk.name to datadog and telemetry.sdk.version to our own version in https://github.com/DataDog/dd-trace-rs/pull/196
- Fix rpc.grpc.status_code stats serialization in https://github.com/DataDog/libdatadog/pull/1780
- Tag spans with sampling rate (_dd.p.ksr) in https://github.com/DataDog/dd-trace-rs/pull/180


## 0.3.1 (Mar 17, 2026)

- Fix sampling effective rate reporting in spans, as it was being truncated in https://github.com/DataDog/dd-trace-rs/pull/183
- Fix appsec decision maker sampling decision from user_keep/user_drop to auto_keep/auto_drop in https://github.com/DataDog/dd-trace-rs/pull/183
- Add trace stat aggregation on the rpc.grpc.status_code attribute (and a couple others) in https://github.com/DataDog/libdatadog/pull/1701

## 0.3.0 (Feb 27, 2026)

- Add OTEL metrics support in https://github.com/DataDog/dd-trace-rs/pull/127
- add OTEL logs support in https://github.com/DataDog/dd-trace-rs/pull/144
- Remove error logs on transient trace export issues in https://github.com/DataDog/dd-trace-rs/pull/148

## 0.2.1 (Dec 11, 2025)

- Fix Remote Config path parsing
- Fix version reporting

## 0.2.0 (Dec 01, 2025)

- Remove private APIs from public exports
- Remove deprecated API to instantiate the SDK
- Refactor import paths for configurations
- Mark the library as out of preview in the README

## 0.1.0 (Nov 21, 2025)

- Initial release
