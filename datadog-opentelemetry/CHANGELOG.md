# Changelog

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
