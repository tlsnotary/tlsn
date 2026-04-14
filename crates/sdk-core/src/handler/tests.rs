//! Tests for handler-based range extraction.

use crate::types::{
    Handler, HandlerAction, HandlerParams, HandlerPart, HandlerType, HashAlgorithm,
};

use super::compute_reveal;

const REQUEST: &[u8] = b"GET /api/users HTTP/1.1\r\n\
Host: api.example.com\r\n\
Authorization: Bearer secret-token\r\n\
Content-Type: application/json\r\n\
\r\n";

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n\
Content-Length: 52\r\n\
\r\n\
{\"screen_name\": \"alice\", \"verified\": true, \"id\": 42}";

/// Helper: run compute_reveal with a single handler.
fn reveal_one(handler: Handler) -> super::ComputeRevealOutput {
    compute_reveal(REQUEST, RESPONSE, &[handler]).expect("compute_reveal failed")
}

/// Helper: extract the actual bytes from raw data given ranges.
fn extract_bytes<'a>(raw: &'a [u8], ranges: &[std::ops::Range<usize>]) -> Vec<&'a [u8]> {
    ranges.iter().map(|r| &raw[r.clone()]).collect()
}

// ---- Start line / Method / Target / StatusCode ----

#[test]
fn test_start_line_request() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::StartLine,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    // Start line includes "GET /api/users HTTP/1.1\r\n"
    assert!(text.contains("GET"));
    assert!(text.contains("/api/users"));
    assert!(text.contains("HTTP/1.1"));
}

#[test]
fn test_start_line_response() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::StartLine,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(RESPONSE, &output.reveal.recv);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    assert!(text.contains("200"));
    assert!(text.contains("OK"));
    assert!(text.contains("HTTP/1.1"));
}

#[test]
fn test_method() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::Method,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    assert_eq!(bytes, vec![b"GET".as_slice()]);
}

#[test]
fn test_request_target() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::RequestTarget,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    assert_eq!(bytes, vec![b"/api/users".as_slice()]);
}

#[test]
fn test_status_code() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::StatusCode,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(RESPONSE, &output.reveal.recv);
    assert_eq!(bytes, vec![b"200".as_slice()]);
}

#[test]
fn test_method_on_response_errors() {
    let result = compute_reveal(
        REQUEST,
        RESPONSE,
        &[Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Method,
            action: HandlerAction::Reveal,
            params: None,
            algorithm: None,
        }],
    );
    assert!(result.is_err());
}

#[test]
fn test_status_code_on_request_errors() {
    let result = compute_reveal(
        REQUEST,
        RESPONSE,
        &[Handler {
            handler_type: HandlerType::Sent,
            part: HandlerPart::StatusCode,
            action: HandlerAction::Reveal,
            params: None,
            algorithm: None,
        }],
    );
    assert!(result.is_err());
}

// ---- Protocol ----

#[test]
fn test_protocol_request() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::Protocol,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    // Protocol should contain HTTP/1.1 and surrounding whitespace/CRLF,
    // but NOT the method or target.
    assert!(text.contains("HTTP/1.1"));
    assert!(!text.contains("GET"));
    assert!(!text.contains("/api/users"));
}

// ---- Headers ----

#[test]
fn test_headers_all() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::Headers,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    assert!(text.contains("Host"));
    assert!(text.contains("Authorization"));
    assert!(text.contains("Content-Type"));
}

#[test]
fn test_headers_specific_key() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::Headers,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            key: Some("Host".to_string()),
            ..Default::default()
        }),
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    assert!(text.contains("Host"));
    assert!(text.contains("api.example.com"));
    // Should NOT include other headers
    assert!(!text.contains("Authorization"));
}

#[test]
fn test_headers_hide_key() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::Headers,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            key: Some("Authorization".to_string()),
            hide_key: Some(true),
            ..Default::default()
        }),
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    // Should reveal only the value
    assert!(text.contains("Bearer secret-token"));
    assert!(!text.contains("Authorization"));
}

#[test]
fn test_headers_hide_value() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::Headers,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            key: Some("Authorization".to_string()),
            hide_value: Some(true),
            ..Default::default()
        }),
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    // Should reveal header name but not value
    assert!(text.contains("Authorization"));
    assert!(!text.contains("Bearer secret-token"));
}

#[test]
fn test_headers_hide_both_errors() {
    let result = compute_reveal(
        REQUEST,
        RESPONSE,
        &[Handler {
            handler_type: HandlerType::Sent,
            part: HandlerPart::Headers,
            action: HandlerAction::Reveal,
            params: Some(HandlerParams {
                key: Some("Host".to_string()),
                hide_key: Some(true),
                hide_value: Some(true),
                ..Default::default()
            }),
            algorithm: None,
        }],
    );
    assert!(result.is_err());
}

// ---- Body ----

#[test]
fn test_body_entire() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::Body,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    let bytes = extract_bytes(RESPONSE, &output.reveal.recv);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    assert!(text.contains("screen_name"));
    assert!(text.contains("alice"));
}

#[test]
fn test_body_json_path() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::Body,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            content_type: Some("json".to_string()),
            path: Some("screen_name".to_string()),
            ..Default::default()
        }),
        algorithm: None,
    });

    let bytes = extract_bytes(RESPONSE, &output.reveal.recv);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    assert!(text.contains("screen_name"));
    assert!(text.contains("alice"));
}

#[test]
fn test_body_json_hide_key() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::Body,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            content_type: Some("json".to_string()),
            path: Some("screen_name".to_string()),
            hide_key: Some(true),
            ..Default::default()
        }),
        algorithm: None,
    });

    let bytes = extract_bytes(RESPONSE, &output.reveal.recv);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    // Should reveal only the value "alice", not the key "screen_name"
    assert!(text.contains("alice"));
    assert!(!text.contains("screen_name"));
}

#[test]
fn test_body_json_hide_value() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::Body,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            content_type: Some("json".to_string()),
            path: Some("screen_name".to_string()),
            hide_value: Some(true),
            ..Default::default()
        }),
        algorithm: None,
    });

    let bytes = extract_bytes(RESPONSE, &output.reveal.recv);
    let combined: Vec<u8> = bytes.into_iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    // Should reveal the key but not the value
    assert!(text.contains("screen_name"));
    assert!(!text.contains("alice"));
}

// ---- ALL ----

#[test]
fn test_all_entire() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::All,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    });

    assert_eq!(output.reveal.sent.len(), 1);
    assert_eq!(output.reveal.sent[0], 0..REQUEST.len());
}

#[test]
fn test_all_regex() {
    let output = reveal_one(Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::All,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            content_type: Some("regex".to_string()),
            regex: Some(r"Bearer [A-Za-z0-9\-]+".to_string()),
            ..Default::default()
        }),
        algorithm: None,
    });

    let bytes = extract_bytes(REQUEST, &output.reveal.sent);
    assert_eq!(bytes.len(), 1);
    assert_eq!(bytes[0], b"Bearer secret-token");
}

// ---- Mixed handlers ----

#[test]
fn test_multiple_handlers() {
    let handlers = vec![
        Handler {
            handler_type: HandlerType::Sent,
            part: HandlerPart::StartLine,
            action: HandlerAction::Reveal,
            params: None,
            algorithm: None,
        },
        Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::StatusCode,
            action: HandlerAction::Reveal,
            params: None,
            algorithm: None,
        },
        Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Body,
            action: HandlerAction::Reveal,
            params: Some(HandlerParams {
                content_type: Some("json".to_string()),
                path: Some("screen_name".to_string()),
                hide_key: Some(true),
                ..Default::default()
            }),
            algorithm: None,
        },
    ];

    let output = compute_reveal(REQUEST, RESPONSE, &handlers).unwrap();

    // Sent should have start line ranges
    assert!(!output.reveal.sent.is_empty());
    // Recv should have status code + body ranges
    assert!(output.reveal.recv.len() >= 2);
    // Annotated ranges should match
    assert_eq!(
        output.sent_ranges_with_handlers.len(),
        output.reveal.sent.len()
    );
    assert_eq!(
        output.recv_ranges_with_handlers.len(),
        output.reveal.recv.len()
    );
}

// ---- Array access with dot notation ----

#[test]
fn test_json_body_dot_notation_array() {
    let body = r#"{"items":[{"name":"Track One"},{"name":"Track Two"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let output = compute_reveal(
        REQUEST,
        response.as_bytes(),
        &[Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Body,
            action: HandlerAction::Reveal,
            params: Some(HandlerParams {
                content_type: Some("json".to_string()),
                path: Some("items.0.name".to_string()),
                ..Default::default()
            }),
            algorithm: None,
        }],
    )
    .unwrap();

    let bytes = extract_bytes(response.as_bytes(), &output.reveal.recv);
    let text = std::str::from_utf8(bytes[0]).unwrap();
    assert!(
        text.contains("Track One"),
        "Expected 'Track One' in: {text}"
    );
}

// ---- Serde wire compatibility ----

#[test]
fn test_handler_serde_roundtrip() {
    let handler = Handler {
        handler_type: HandlerType::Sent,
        part: HandlerPart::Body,
        action: HandlerAction::Reveal,
        params: Some(HandlerParams {
            content_type: Some("json".to_string()),
            path: Some("screen_name".to_string()),
            hide_key: Some(true),
            ..Default::default()
        }),
        algorithm: None,
    };

    let json = serde_json::to_string(&handler).unwrap();
    let deserialized: Handler = serde_json::from_str(&json).unwrap();
    assert_eq!(handler, deserialized);
}

#[test]
fn test_handler_serde_wire_format() {
    // Verify JSON matches what existing TypeScript plugins produce
    let json_str = r#"{"type":"SENT","part":"BODY","action":"REVEAL","params":{"type":"json","path":"screen_name","hideKey":true}}"#;
    let handler: Handler = serde_json::from_str(json_str).unwrap();

    assert_eq!(handler.handler_type, HandlerType::Sent);
    assert_eq!(handler.part, HandlerPart::Body);
    assert_eq!(handler.action, HandlerAction::Reveal);
    let params = handler.params.as_ref().unwrap();
    assert_eq!(params.content_type.as_deref(), Some("json"));
    assert_eq!(params.path.as_deref(), Some("screen_name"));
    assert_eq!(params.hide_key, Some(true));
}

#[test]
fn test_handler_serde_all_parts() {
    // Verify all HandlerPart variants serialize correctly
    let parts = [
        (HandlerPart::StartLine, "START_LINE"),
        (HandlerPart::Protocol, "PROTOCOL"),
        (HandlerPart::Method, "METHOD"),
        (HandlerPart::RequestTarget, "REQUEST_TARGET"),
        (HandlerPart::StatusCode, "STATUS_CODE"),
        (HandlerPart::Headers, "HEADERS"),
        (HandlerPart::Body, "BODY"),
        (HandlerPart::All, "ALL"),
    ];

    for (part, expected) in parts {
        let handler = Handler {
            handler_type: HandlerType::Sent,
            part,
            action: HandlerAction::Reveal,
            params: None,
            algorithm: None,
        };
        let json = serde_json::to_value(&handler).unwrap();
        assert_eq!(
            json["part"], expected,
            "HandlerPart::{part:?} should serialize to {expected}"
        );
    }
}

// ---- HASH action ----

#[test]
fn test_hash_action_splits_ranges() {
    // Mix of REVEAL and HASH handlers: HASH ranges go to commit, REVEAL to reveal.
    let handlers = vec![
        Handler {
            handler_type: HandlerType::Sent,
            part: HandlerPart::StartLine,
            action: HandlerAction::Reveal,
            params: None,
            algorithm: None,
        },
        Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Body,
            action: HandlerAction::Hash,
            params: Some(HandlerParams {
                content_type: Some("json".to_string()),
                path: Some("screen_name".to_string()),
                hide_key: Some(true),
                ..Default::default()
            }),
            algorithm: None,
        },
    ];

    let output = compute_reveal(REQUEST, RESPONSE, &handlers).unwrap();

    // Sent start line should be in reveal (action: REVEAL)
    assert!(!output.reveal.sent.is_empty());
    // Recv body should NOT be in reveal (action: HASH)
    assert!(output.reveal.recv.is_empty());
    // Commit should be present with recv ranges
    let commit = output
        .commit
        .expect("commit should be Some when HASH handlers are used");
    assert!(!commit.recv.is_empty());
    assert!(commit.sent.is_empty());
    // Per-range algorithm is None (BLAKE3 default applied downstream)
    assert!(commit.recv[0].algorithm.is_none());
}

#[test]
fn test_hash_action_with_algorithm() {
    let handler = Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::Body,
        action: HandlerAction::Hash,
        params: None,
        algorithm: Some(HashAlgorithm::Sha256),
    };

    let output = reveal_one(handler);

    let commit = output.commit.expect("commit should be Some");
    assert!(!commit.recv.is_empty());
    // Each range carries its handler's algorithm
    assert_eq!(commit.recv[0].algorithm, Some(HashAlgorithm::Sha256));
}

#[test]
fn test_reveal_only_has_no_commit() {
    let handler = Handler {
        handler_type: HandlerType::Recv,
        part: HandlerPart::Body,
        action: HandlerAction::Reveal,
        params: None,
        algorithm: None,
    };

    let output = reveal_one(handler);
    assert!(output.commit.is_none());
}

#[test]
fn test_pedersen_alias_deserializes_to_hash() {
    let json_str = r#"{"type":"RECV","part":"BODY","action":"PEDERSEN"}"#;
    let handler: Handler = serde_json::from_str(json_str).unwrap();
    assert!(handler.action.is_hash());
}

#[test]
fn test_hash_action_serde_roundtrip() {
    let json_str = r#"{"type":"RECV","part":"BODY","action":"HASH","algorithm":"SHA256"}"#;
    let handler: Handler = serde_json::from_str(json_str).unwrap();

    assert_eq!(handler.action, HandlerAction::Hash);
    assert_eq!(handler.algorithm, Some(HashAlgorithm::Sha256));

    // Roundtrip
    let serialized = serde_json::to_string(&handler).unwrap();
    let deserialized: Handler = serde_json::from_str(&serialized).unwrap();
    assert_eq!(handler, deserialized);
}

#[test]
fn test_hash_action_wire_format_without_algorithm() {
    // Plugins may send HASH without algorithm — should default to None (BLAKE3 at runtime)
    let json_str = r#"{"type":"RECV","part":"BODY","action":"HASH"}"#;
    let handler: Handler = serde_json::from_str(json_str).unwrap();

    assert_eq!(handler.action, HandlerAction::Hash);
    assert!(handler.algorithm.is_none());
}

#[test]
fn test_mixed_hash_algorithms_per_range() {
    // Two HASH handlers with different algorithms produce per-range algorithms.
    let handlers = vec![
        Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Body,
            action: HandlerAction::Hash,
            params: Some(HandlerParams {
                content_type: Some("json".to_string()),
                path: Some("screen_name".to_string()),
                ..Default::default()
            }),
            algorithm: Some(HashAlgorithm::Sha256),
        },
        Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Body,
            action: HandlerAction::Hash,
            params: Some(HandlerParams {
                content_type: Some("json".to_string()),
                path: Some("verified".to_string()),
                ..Default::default()
            }),
            algorithm: Some(HashAlgorithm::Keccak256),
        },
    ];

    let output = compute_reveal(REQUEST, RESPONSE, &handlers).unwrap();
    let commit = output.commit.expect("commit should be Some");

    assert_eq!(commit.recv.len(), 2);
    assert_eq!(commit.recv[0].algorithm, Some(HashAlgorithm::Sha256));
    assert_eq!(commit.recv[1].algorithm, Some(HashAlgorithm::Keccak256));
}
