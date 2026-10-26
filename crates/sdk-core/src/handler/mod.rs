//! Handler-based range extraction from HTTP transcripts.
//!
//! This module provides the [`compute_reveal`] function that maps plugin
//! [`Handler`] configurations to byte ranges suitable for
//! [`Reveal`](crate::Reveal).
//!
//! It uses [spansy] for HTTP/JSON parsing with byte-range tracking, replacing
//! the TypeScript `Parser` + `RangeExtractor` logic.

mod extract;

#[cfg(test)]
mod tests;

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, SdkError},
    types::{Commit, CommitRange, Handler, HandlerAction, HandlerPart, HandlerType, Reveal},
};

/// A byte range annotated with the handler that produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeWithHandler {
    /// Start of the byte range (inclusive).
    pub start: usize,
    /// End of the byte range (exclusive).
    pub end: usize,
    /// The handler that produced this range.
    pub handler: Handler,
}

/// Output from [`compute_reveal`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeRevealOutput {
    /// The `Reveal` struct ready for `SdkProver::reveal()`.
    pub reveal: Reveal,
    /// Ranges to hash-commit (the verifier receives `H(plaintext, blinder)`).
    /// `None` when no handlers use `action: HASH`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<Commit>,
    /// Sent ranges annotated with their originating handler.
    pub sent_ranges_with_handlers: Vec<RangeWithHandler>,
    /// Received ranges annotated with their originating handler.
    pub recv_ranges_with_handlers: Vec<RangeWithHandler>,
}

/// Parses HTTP request/response transcripts and maps handlers to byte ranges.
///
/// This is the Rust equivalent of the TypeScript `processHandlers()` function.
/// It uses spansy to parse the raw HTTP bytes, then applies each handler's
/// configuration to extract the relevant byte ranges.
///
/// # Arguments
///
/// * `sent` - Raw bytes of the HTTP request (sent data).
/// * `recv` - Raw bytes of the HTTP response (received data).
/// * `handlers` - Slice of handler configurations from the plugin.
///
/// # Returns
///
/// A [`ComputeRevealOutput`] containing:
/// - A [`Reveal`] with sent/recv ranges for `SdkProver::reveal()`
/// - Annotated ranges mapping each range back to its handler
pub fn compute_reveal(
    sent: &[u8],
    recv: &[u8],
    handlers: &[Handler],
) -> Result<ComputeRevealOutput> {
    // `ALL` handlers select raw byte ranges, so a direction is only parsed when
    // some handler needs its HTTP structure. Parsing is strict (e.g. a body
    // declared `application/json` must be JSON), and an API whose body is
    // opaque under that content type would otherwise be unprovable.
    let needs_parse = |sent_side: bool| {
        handlers.iter().any(|h| {
            matches!(h.handler_type, HandlerType::Sent) == sent_side
                && !matches!(h.part, HandlerPart::All)
        })
    };
    let request = needs_parse(true)
        .then(|| spansy::http::parse_request(sent))
        .transpose()
        .map_err(|e| SdkError::handler(format!("failed to parse HTTP request: {e}")))?;
    let response = needs_parse(false)
        .then(|| spansy::http::parse_response(recv))
        .transpose()
        .map_err(|e| SdkError::handler(format!("failed to parse HTTP response: {e}")))?;

    let mut reveal_sent: Vec<Range<usize>> = Vec::new();
    let mut reveal_recv: Vec<Range<usize>> = Vec::new();
    let mut commit_sent: Vec<CommitRange> = Vec::new();
    let mut commit_recv: Vec<CommitRange> = Vec::new();
    let mut sent_with_handlers: Vec<RangeWithHandler> = Vec::new();
    let mut recv_with_handlers: Vec<RangeWithHandler> = Vec::new();

    let sent_msg = request.as_ref().map(extract::HttpMessage::from);
    let recv_msg = response.as_ref().map(extract::HttpMessage::from);

    for handler in handlers {
        let (msg, raw) = match handler.handler_type {
            HandlerType::Sent => (sent_msg.as_ref(), sent),
            HandlerType::Recv => (recv_msg.as_ref(), recv),
        };
        let extracted = match msg {
            Some(msg) => extract::extract_ranges(handler, msg, raw)?,
            // Only reachable for `ALL` handlers (see `needs_parse`).
            None => extract::extract_all(handler, raw)?,
        };

        let with_handlers_vec = match handler.handler_type {
            HandlerType::Sent => &mut sent_with_handlers,
            HandlerType::Recv => &mut recv_with_handlers,
        };

        for range in &extracted {
            with_handlers_vec.push(RangeWithHandler {
                start: range.start,
                end: range.end,
                handler: handler.clone(),
            });
        }

        if let HandlerAction::Hash { algorithm } = handler.action {
            let commit_vec = match handler.handler_type {
                HandlerType::Sent => &mut commit_sent,
                HandlerType::Recv => &mut commit_recv,
            };
            for range in extracted {
                commit_vec.push(CommitRange {
                    start: range.start,
                    end: range.end,
                    algorithm,
                });
            }
        } else {
            let reveal_vec = match handler.handler_type {
                HandlerType::Sent => &mut reveal_sent,
                HandlerType::Recv => &mut reveal_recv,
            };
            reveal_vec.extend(extracted);
        }
    }

    let commit = if commit_sent.is_empty() && commit_recv.is_empty() {
        None
    } else {
        Some(Commit {
            sent: commit_sent,
            recv: commit_recv,
        })
    };

    Ok(ComputeRevealOutput {
        reveal: Reveal {
            sent: reveal_sent,
            recv: reveal_recv,
            server_identity: true,
        },
        commit,
        sent_ranges_with_handlers: sent_with_handlers,
        recv_ranges_with_handlers: recv_with_handlers,
    })
}
