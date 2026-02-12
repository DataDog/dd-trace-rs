# Changelog

## 0.3.0 (TBD)

### Added
- Add OpenTelemetry Metrics API support with OTLP export via gRPC (default) and HTTP/protobuf protocols (#127)
- Add OpenTelemetry Logs API support with OTLP export via gRPC and HTTP/protobuf protocols (#144)
- Add sync export mode for trace exporter (gated behind test-utils feature) (#149)
- Add enhanced config reporting for better visibility (#126)

### Changed
- Remove error log on trace export failures (#148)

### Fixed
- Update `lru` dependency to resolve a low-risk vulnerability (#145)

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
