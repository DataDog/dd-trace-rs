// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! pprof protobuf timeline serializer.
//!
//! This module produces pprof protobuf format with timeline-specific labels,
//! which can be visualized in pprof-compatible tools and potentially Datadog's
//! timeline viewer.

use std::collections::HashMap;
use std::io::Write;
use std::time::SystemTime;

use flate2::write::GzEncoder;
use flate2::Compression;
use prost::Message;

use super::{SerializeError, SerializedTimeline, TimelineSerializer};
use crate::tokio_timeline::buffer::OwnedEvent;

/// pprof protobuf message definitions.
/// Field numbers match the official pprof proto:
/// https://github.com/google/pprof/blob/main/proto/profile.proto
mod proto {
    /// A complete profile, the format used by pprof.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Profile {
        /// Sample value types (e.g., "wall-time", "nanoseconds").
        #[prost(message, repeated, tag = "1")]
        pub sample_type: Vec<ValueType>,
        /// Samples in this profile.
        #[prost(message, repeated, tag = "2")]
        pub sample: Vec<Sample>,
        /// Mappings from address to source.
        #[prost(message, repeated, tag = "3")]
        pub mapping: Vec<Mapping>,
        /// Locations referenced by samples.
        #[prost(message, repeated, tag = "4")]
        pub location: Vec<Location>,
        /// Functions referenced by locations.
        #[prost(message, repeated, tag = "5")]
        pub function: Vec<Function>,
        /// List of strings used in the profile (index 0 is always empty string).
        #[prost(bytes = "vec", repeated, tag = "6")]
        pub string_table: Vec<Vec<u8>>,
        /// Index into string_table for frames to drop.
        #[prost(int64, tag = "7")]
        pub drop_frames: i64,
        /// Index into string_table for frames to keep.
        #[prost(int64, tag = "8")]
        pub keep_frames: i64,
        /// Time of profile collection (nanoseconds since epoch).
        #[prost(int64, tag = "9")]
        pub time_nanos: i64,
        /// Duration of profile collection (nanoseconds).
        #[prost(int64, tag = "10")]
        pub duration_nanos: i64,
        /// Profile period type.
        #[prost(message, optional, tag = "11")]
        pub period_type: Option<ValueType>,
        /// Profile period.
        #[prost(int64, tag = "12")]
        pub period: i64,
        /// Comment strings (indices into string_table).
        #[prost(int64, repeated, tag = "13")]
        pub comment: Vec<i64>,
        /// Default sample type index.
        #[prost(int64, tag = "14")]
        pub default_sample_type: i64,
    }

    /// Description of a sample type.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ValueType {
        #[prost(int64, tag = "1")]
        pub type_: i64,
        #[prost(int64, tag = "2")]
        pub unit: i64,
    }

    /// A sample with values and labels.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Sample {
        /// Indices into the location table.
        #[prost(uint64, repeated, tag = "1")]
        pub location_id: Vec<u64>,
        /// Values for each sample type.
        #[prost(int64, repeated, tag = "2")]
        pub value: Vec<i64>,
        /// Labels with string key/value pairs.
        #[prost(message, repeated, tag = "3")]
        pub label: Vec<Label>,
    }

    /// A label for a sample.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Label {
        #[prost(int64, tag = "1")]
        pub key: i64,
        #[prost(int64, tag = "2")]
        pub str: i64,
        #[prost(int64, tag = "3")]
        pub num: i64,
        #[prost(int64, tag = "4")]
        pub num_unit: i64,
    }

    /// Memory mapping information.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Mapping {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(uint64, tag = "2")]
        pub memory_start: u64,
        #[prost(uint64, tag = "3")]
        pub memory_limit: u64,
        #[prost(uint64, tag = "4")]
        pub file_offset: u64,
        #[prost(int64, tag = "5")]
        pub filename: i64,
        #[prost(int64, tag = "6")]
        pub build_id: i64,
        #[prost(bool, tag = "7")]
        pub has_functions: bool,
        #[prost(bool, tag = "8")]
        pub has_filenames: bool,
        #[prost(bool, tag = "9")]
        pub has_line_numbers: bool,
        #[prost(bool, tag = "10")]
        pub has_inline_frames: bool,
    }

    /// Source location information.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Location {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(uint64, tag = "2")]
        pub mapping_id: u64,
        #[prost(uint64, tag = "3")]
        pub address: u64,
        #[prost(message, repeated, tag = "4")]
        pub line: Vec<Line>,
        #[prost(bool, tag = "5")]
        pub is_folded: bool,
    }

    /// Source line information.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Line {
        #[prost(uint64, tag = "1")]
        pub function_id: u64,
        #[prost(int64, tag = "2")]
        pub line: i64,
    }

    /// Function information.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Function {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(int64, tag = "2")]
        pub name: i64,
        #[prost(int64, tag = "3")]
        pub system_name: i64,
        #[prost(int64, tag = "4")]
        pub filename: i64,
        #[prost(int64, tag = "5")]
        pub start_line: i64,
    }
}

/// Serializer for pprof protobuf timeline format.
#[derive(Debug, Default)]
pub struct PprofTimelineSerializer {
    /// String table for deduplication.
    string_table: HashMap<String, i64>,
    /// String table entries in order.
    string_table_entries: Vec<String>,
    /// Location table for deduplication.
    location_table: HashMap<String, u64>,
    /// Location entries.
    locations: Vec<proto::Location>,
    /// Function entries.
    functions: Vec<proto::Function>,
    /// Next location ID.
    next_location_id: u64,
    /// Next function ID.
    next_function_id: u64,
}

impl PprofTimelineSerializer {
    /// Creates a new pprof timeline serializer.
    pub fn new() -> Self {
        Self {
            string_table: HashMap::new(),
            string_table_entries: Vec::new(),
            location_table: HashMap::new(),
            locations: Vec::new(),
            functions: Vec::new(),
            next_location_id: 1, // IDs start at 1
            next_function_id: 1,
        }
    }

    /// Gets or creates a string ID for the given string.
    fn get_or_create_string_id(&mut self, s: &str) -> i64 {
        if let Some(&id) = self.string_table.get(s) {
            return id;
        }
        let id = self.string_table_entries.len() as i64;
        self.string_table.insert(s.to_string(), id);
        self.string_table_entries.push(s.to_string());
        id
    }

    /// Gets or creates a location ID for the given location string.
    /// Creates both a Function and Location entry.
    fn get_or_create_location_id(&mut self, location: &str) -> u64 {
        if location.is_empty() {
            return 0;
        }
        if let Some(&id) = self.location_table.get(location) {
            return id;
        }

        // Create function entry
        let func_name_id = self.get_or_create_string_id(location);
        let func_id = self.next_function_id;
        self.next_function_id += 1;

        self.functions.push(proto::Function {
            id: func_id,
            name: func_name_id,
            system_name: func_name_id,
            filename: 0, // empty string
            start_line: 0,
        });

        // Create location entry
        let loc_id = self.next_location_id;
        self.next_location_id += 1;

        self.locations.push(proto::Location {
            id: loc_id,
            mapping_id: 0,
            address: 0,
            line: vec![proto::Line {
                function_id: func_id,
                line: 0,
            }],
            is_folded: false,
        });

        self.location_table.insert(location.to_string(), loc_id);
        loc_id
    }

    /// Resets the string table for a new profile.
    fn reset(&mut self) {
        self.string_table.clear();
        self.string_table_entries.clear();
        self.location_table.clear();
        self.locations.clear();
        self.functions.clear();
        self.next_location_id = 1;
        self.next_function_id = 1;
        // Add empty string at index 0
        self.get_or_create_string_id("");
    }

    /// Creates a pprof profile from timeline events.
    fn create_profile(
        &mut self,
        events: &[OwnedEvent],
        batch_start: SystemTime,
        batch_end: SystemTime,
    ) -> proto::Profile {
        self.reset();

        // Pre-register common strings
        // IMPORTANT: "thread id" uses a space (not underscore) - this is required by Datadog backend
        let wall_time_id = self.get_or_create_string_id("wall-time");
        let nanoseconds_id = self.get_or_create_string_id("nanoseconds");
        let thread_id_key = self.get_or_create_string_id("thread id"); // Space, not underscore!
        let thread_name_key = self.get_or_create_string_id("thread name");
        let state_key = self.get_or_create_string_id("state");
        let end_timestamp_key = self.get_or_create_string_id("end_timestamp_ns");
        let running_state = self.get_or_create_string_id("running");

        // Build samples from PollStart + PollEnd pairs
        let samples = self.build_samples_from_polls(
            events,
            thread_id_key,
            thread_name_key,
            state_key,
            end_timestamp_key,
            running_state,
        );

        // Calculate time span
        let time_nanos = batch_start
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let duration_nanos = batch_end
            .duration_since(batch_start)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Build string table bytes
        let string_table: Vec<Vec<u8>> = self
            .string_table_entries
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();

        // Take ownership of locations and functions
        let locations = std::mem::take(&mut self.locations);
        let functions = std::mem::take(&mut self.functions);

        proto::Profile {
            sample_type: vec![proto::ValueType {
                type_: wall_time_id,
                unit: nanoseconds_id,
            }],
            sample: samples,
            mapping: vec![],
            location: locations,
            function: functions,
            string_table,
            drop_frames: 0,
            keep_frames: 0,
            time_nanos,
            duration_nanos,
            period_type: Some(proto::ValueType {
                type_: wall_time_id,
                unit: nanoseconds_id,
            }),
            period: 1,
            comment: vec![],
            default_sample_type: 0,
        }
    }

    /// Builds samples from poll events.
    fn build_samples_from_polls(
        &mut self,
        events: &[OwnedEvent],
        thread_id_key: i64,
        thread_name_key: i64,
        state_key: i64,
        end_timestamp_key: i64,
        running_state: i64,
    ) -> Vec<proto::Sample> {
        let mut samples = Vec::new();

        // Track active polls per worker
        // worker_id -> (task_id, start_time, location)
        let mut active_polls: HashMap<u8, (u64, u64, String)> = HashMap::new();

        for event in events {
            match event {
                OwnedEvent::PollStart {
                    timestamp_nanos,
                    worker_id,
                    task_id,
                    location,
                } => {
                    active_polls.insert(*worker_id, (*task_id, *timestamp_nanos, location.clone()));
                }
                OwnedEvent::PollEnd {
                    timestamp_nanos,
                    worker_id,
                } => {
                    if let Some((task_id, start_time, location)) = active_polls.remove(worker_id) {
                        let duration = timestamp_nanos.saturating_sub(start_time);
                        if duration > 0 {
                            // Create location/function for this poll
                            let location_id = self.get_or_create_location_id(&location);

                            // Create thread name string for this worker
                            let thread_name = format!("tokio-worker-{}", worker_id);
                            let thread_name_str_id = self.get_or_create_string_id(&thread_name);

                            let sample = proto::Sample {
                                location_id: if location_id > 0 {
                                    vec![location_id]
                                } else {
                                    vec![]
                                },
                                value: vec![duration as i64],
                                label: vec![
                                    // "thread id" - required by Datadog backend (uses task_id as thread identifier)
                                    proto::Label {
                                        key: thread_id_key,
                                        str: 0,
                                        num: task_id as i64,
                                        num_unit: 0,
                                    },
                                    // "thread name" - human-readable name
                                    proto::Label {
                                        key: thread_name_key,
                                        str: thread_name_str_id,
                                        num: 0,
                                        num_unit: 0,
                                    },
                                    // "state" - running state
                                    proto::Label {
                                        key: state_key,
                                        str: running_state,
                                        num: 0,
                                        num_unit: 0,
                                    },
                                    // "end_timestamp_ns" - when this sample ended
                                    proto::Label {
                                        key: end_timestamp_key,
                                        str: 0,
                                        num: *timestamp_nanos as i64,
                                        num_unit: 0,
                                    },
                                ],
                            };
                            samples.push(sample);
                        }
                    }
                }
                _ => {}
            }
        }

        samples
    }
}

impl TimelineSerializer for PprofTimelineSerializer {
    fn serialize(
        &mut self,
        events: &[OwnedEvent],
        batch_start: SystemTime,
        batch_end: SystemTime,
    ) -> Result<SerializedTimeline, SerializeError> {
        let profile = self.create_profile(events, batch_start, batch_end);

        // Encode to protobuf
        let mut buf = Vec::new();
        profile
            .encode(&mut buf)
            .map_err(|e| SerializeError::EncodingError(e.to_string()))?;

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&buf)
            .map_err(|e| SerializeError::CompressionError(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| SerializeError::CompressionError(e.to_string()))?;

        Ok(SerializedTimeline {
            data: compressed,
            name: "timeline.pprof",
            filename: "timeline.pprof",
            content_type: "application/octet-stream",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_table() {
        let mut serializer = PprofTimelineSerializer::new();
        serializer.reset();

        let id1 = serializer.get_or_create_string_id("test");
        let id2 = serializer.get_or_create_string_id("test");
        assert_eq!(id1, id2);

        let id3 = serializer.get_or_create_string_id("other");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_serialize_empty() {
        let mut serializer = PprofTimelineSerializer::new();
        let result = serializer
            .serialize(&[], SystemTime::now(), SystemTime::now())
            .unwrap();

        assert!(!result.data.is_empty());
        assert_eq!(result.filename, "timeline.pprof");
        assert_eq!(result.content_type, "application/octet-stream");
    }

    #[test]
    fn test_serialize_with_polls() {
        let mut serializer = PprofTimelineSerializer::new();
        let events = vec![
            OwnedEvent::PollStart {
                timestamp_nanos: 1000,
                worker_id: 0,
                task_id: 1,
                location: "main.rs:10".to_string(),
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 2000,
                worker_id: 0,
            },
        ];

        let result = serializer
            .serialize(&events, SystemTime::now(), SystemTime::now())
            .unwrap();

        // Should produce valid gzip data
        assert!(!result.data.is_empty());

        // Verify it's valid gzip (magic bytes)
        assert_eq!(result.data[0], 0x1f);
        assert_eq!(result.data[1], 0x8b);
    }

    #[test]
    fn test_build_samples() {
        let mut serializer = PprofTimelineSerializer::new();
        serializer.reset();

        // Use the correct label names that Datadog backend expects
        let thread_id_key = serializer.get_or_create_string_id("thread id"); // Space, not underscore!
        let thread_name_key = serializer.get_or_create_string_id("thread name");
        let state_key = serializer.get_or_create_string_id("state");
        let end_timestamp_key = serializer.get_or_create_string_id("end_timestamp_ns");
        let running_state = serializer.get_or_create_string_id("running");

        let events = vec![
            OwnedEvent::PollStart {
                timestamp_nanos: 1000,
                worker_id: 0,
                task_id: 1,
                location: "main.rs:10".to_string(),
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 2000,
                worker_id: 0,
            },
            OwnedEvent::PollStart {
                timestamp_nanos: 3000,
                worker_id: 1,
                task_id: 2,
                location: "lib.rs:20".to_string(),
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 5000,
                worker_id: 1,
            },
        ];

        let samples = serializer.build_samples_from_polls(
            &events,
            thread_id_key,
            thread_name_key,
            state_key,
            end_timestamp_key,
            running_state,
        );

        assert_eq!(samples.len(), 2);

        // First sample: 2000 - 1000 = 1000 ns
        assert_eq!(samples[0].value, vec![1000]);

        // Second sample: 5000 - 3000 = 2000 ns
        assert_eq!(samples[1].value, vec![2000]);
    }
}
