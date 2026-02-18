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
    types::{Handler, HandlerType, Reveal},
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
    let request = spansy::http::parse_request(sent)
        .map_err(|e| SdkError::handler(format!("failed to parse HTTP request: {e}")))?;
    let response = spansy::http::parse_response(recv)
        .map_err(|e| SdkError::handler(format!("failed to parse HTTP response: {e}")))?;

    let mut sent_ranges: Vec<Range<usize>> = Vec::new();
    let mut recv_ranges: Vec<Range<usize>> = Vec::new();
    let mut sent_with_handlers: Vec<RangeWithHandler> = Vec::new();
    let mut recv_with_handlers: Vec<RangeWithHandler> = Vec::new();

    let sent_msg = extract::HttpMessage::from(&request);
    let recv_msg = extract::HttpMessage::from(&response);

    for handler in handlers {
        let extracted = match handler.handler_type {
            HandlerType::Sent => extract::extract_ranges(handler, &sent_msg, sent)?,
            HandlerType::Recv => extract::extract_ranges(handler, &recv_msg, recv)?,
        };

        let (ranges_vec, with_handlers_vec) = match handler.handler_type {
            HandlerType::Sent => (&mut sent_ranges, &mut sent_with_handlers),
            HandlerType::Recv => (&mut recv_ranges, &mut recv_with_handlers),
        };

        for range in &extracted {
            with_handlers_vec.push(RangeWithHandler {
                start: range.start,
                end: range.end,
                handler: handler.clone(),
            });
        }
        ranges_vec.extend(extracted);
    }

    Ok(ComputeRevealOutput {
        reveal: Reveal {
            sent: sent_ranges,
            recv: recv_ranges,
            server_identity: true,
        },
        sent_ranges_with_handlers: sent_with_handlers,
        recv_ranges_with_handlers: recv_with_handlers,
    })
}
