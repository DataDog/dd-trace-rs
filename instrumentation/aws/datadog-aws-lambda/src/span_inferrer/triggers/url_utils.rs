// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

/// Replaces path segments that look like identifiers (numeric, UUID, GUID, ULID)
/// with `{prev_segment_id}` placeholders to prevent cardinality explosion.
///
/// Skips paths that already contain `{` (API Gateway parameter syntax).
pub(crate) fn parameterize_api_resource(path: &str) -> String {
    if path.contains('{') {
        return path.to_owned();
    }

    let parts: Vec<&str> = path.split('/').collect();
    let mut result: Vec<String> = Vec::with_capacity(parts.len());

    // Leading slash produces an empty first segment — preserve it.
    result.push(String::new());

    for (i, &part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            continue;
        }

        if is_id_segment(part) {
            let param_name = if i > 1 && !parts[i - 1].is_empty() {
                let prev = parts[i - 1];
                let singular = prev.trim_end_matches('s');
                if singular == "id" {
                    "id".to_owned()
                } else {
                    format!("{singular}_id")
                }
            } else {
                "id".to_owned()
            };
            result.push(format!("{{{param_name}}}"));
        } else {
            result.push(part.to_owned());
        }
    }

    result.join("/")
}

fn is_id_segment(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit()) || is_uuid(s) || is_ulid(s)
}

/// UUID / GUID: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (hex digits, case-insensitive)
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    let dashes = [8, 13, 18, 23];
    for (i, &byte) in b.iter().enumerate() {
        if dashes.contains(&i) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// ULID: exactly 26 characters from Crockford's Base32 alphabet (uppercase).
fn is_ulid(s: &str) -> bool {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    s.len() == 26 && s.bytes().all(|b| CROCKFORD.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_numeric_segments() {
        assert_eq!(
            parameterize_api_resource("/users/12345/friends/67890"),
            "/users/{user_id}/friends/{friend_id}"
        );
    }

    #[test]
    fn replaces_uuid_segment() {
        assert_eq!(
            parameterize_api_resource("/orders/550e8400-e29b-41d4-a716-446655440000/details"),
            "/orders/{order_id}/details"
        );
    }

    #[test]
    fn skips_path_with_braces() {
        let path = "/users/{id}/profile";
        assert_eq!(parameterize_api_resource(path), path);
    }

    #[test]
    fn preserves_non_id_segments() {
        assert_eq!(
            parameterize_api_resource("/api/v1/status"),
            "/api/v1/status"
        );
    }

    #[test]
    fn handles_ulid_segment() {
        assert_eq!(
            parameterize_api_resource("/items/01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            "/items/{item_id}"
        );
    }

    #[test]
    fn handles_trailing_id() {
        assert_eq!(parameterize_api_resource("/ids/42"), "/ids/{id}");
    }
}
