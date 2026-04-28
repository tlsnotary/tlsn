//! Range extraction from parsed HTTP messages using spansy.

use std::ops::Range;

use rangeset::{iter::RangeIterator, ops::Set, set::RangeSet};
use spansy::{
    Store,
    http::{Body, BodyContent, Header, Request, Response},
    json::{JsonValue, KeyValue},
};

use crate::{
    error::{Result, SdkError},
    types::{Handler, HandlerParams, HandlerPart},
};

/// Converts a `RangeSet<usize>` to `Vec<Range<usize>>`.
fn rangeset_to_vec(rs: &RangeSet<usize>) -> Vec<Range<usize>> {
    rs.iter().collect()
}

/// Extracts byte ranges from an HTTP request based on a handler.
pub(crate) fn extract_ranges<S: Store>(
    handler: &Handler,
    message: &HttpMessage<'_, S>,
    raw: &[u8],
) -> Result<Vec<Range<usize>>> {
    match handler.part {
        HandlerPart::StartLine => extract_start_line(message),
        HandlerPart::Protocol => extract_protocol(message),
        HandlerPart::Method => extract_method(message),
        HandlerPart::RequestTarget => extract_request_target(message),
        HandlerPart::StatusCode => extract_status_code(message),
        HandlerPart::Headers => extract_headers(handler, message),
        HandlerPart::Body => extract_body(handler, message),
        HandlerPart::All => extract_all(handler, raw),
    }
}

/// Abstraction over Request and Response for shared extraction logic.
pub(crate) enum HttpMessage<'a, S: Store> {
    Request(&'a Request<S>),
    Response(&'a Response<S>),
}

impl<'a, S: Store> From<&'a Request<S>> for HttpMessage<'a, S> {
    fn from(req: &'a Request<S>) -> Self {
        HttpMessage::Request(req)
    }
}

impl<'a, S: Store> From<&'a Response<S>> for HttpMessage<'a, S> {
    fn from(resp: &'a Response<S>) -> Self {
        HttpMessage::Response(resp)
    }
}

impl<S: Store> HttpMessage<'_, S> {
    fn headers(&self) -> &[Header<S>] {
        match self {
            HttpMessage::Request(req) => &req.headers,
            HttpMessage::Response(resp) => &resp.headers,
        }
    }

    fn headers_with_name<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = &'a Header<S>> + 'a> {
        match self {
            HttpMessage::Request(req) => Box::new(req.headers_with_name(name)),
            HttpMessage::Response(resp) => Box::new(resp.headers_with_name(name)),
        }
    }

    fn body(&self) -> Option<&Body<S>> {
        match self {
            HttpMessage::Request(req) => req.body.as_ref(),
            HttpMessage::Response(resp) => resp.body.as_ref(),
        }
    }
}

fn extract_start_line<S: Store>(message: &HttpMessage<'_, S>) -> Result<Vec<Range<usize>>> {
    match message {
        HttpMessage::Request(req) => Ok(rangeset_to_vec(req.request.indices())),
        HttpMessage::Response(resp) => Ok(rangeset_to_vec(resp.status.indices())),
    }
}

fn extract_protocol<S: Store>(message: &HttpMessage<'_, S>) -> Result<Vec<Range<usize>>> {
    // Protocol is the start line minus method/target (request) or code/reason
    // (response).
    match message {
        HttpMessage::Request(req) => {
            let start_line = req.request.indices();
            let method = req.request.method.indices();
            let target = req.request.target.indices();
            let protocol = start_line
                .difference(method)
                .into_set()
                .difference(target)
                .into_set();
            Ok(rangeset_to_vec(&protocol))
        }
        HttpMessage::Response(resp) => {
            let status_line = resp.status.indices();
            let code = resp.status.code.indices();
            let reason = resp.status.reason.indices();
            let protocol = status_line
                .difference(code)
                .into_set()
                .difference(reason)
                .into_set();
            Ok(rangeset_to_vec(&protocol))
        }
    }
}

fn extract_method<S: Store>(message: &HttpMessage<'_, S>) -> Result<Vec<Range<usize>>> {
    match message {
        HttpMessage::Request(req) => Ok(rangeset_to_vec(req.request.method.indices())),
        HttpMessage::Response(_) => Err(SdkError::handler(
            "METHOD handler is only valid for requests (SENT)",
        )),
    }
}

fn extract_request_target<S: Store>(message: &HttpMessage<'_, S>) -> Result<Vec<Range<usize>>> {
    match message {
        HttpMessage::Request(req) => Ok(rangeset_to_vec(req.request.target.indices())),
        HttpMessage::Response(_) => Err(SdkError::handler(
            "REQUEST_TARGET handler is only valid for requests (SENT)",
        )),
    }
}

fn extract_status_code<S: Store>(message: &HttpMessage<'_, S>) -> Result<Vec<Range<usize>>> {
    match message {
        HttpMessage::Request(_) => Err(SdkError::handler(
            "STATUS_CODE handler is only valid for responses (RECV)",
        )),
        HttpMessage::Response(resp) => Ok(rangeset_to_vec(resp.status.code.indices())),
    }
}

fn extract_headers<S: Store>(
    handler: &Handler,
    message: &HttpMessage<'_, S>,
) -> Result<Vec<Range<usize>>> {
    let params = handler.params.as_ref();
    let hide_key = params.and_then(|p| p.hide_key).unwrap_or(false);
    let hide_value = params.and_then(|p| p.hide_value).unwrap_or(false);

    if hide_key && hide_value {
        return Err(SdkError::handler("cannot hide both key and value"));
    }

    let mut ranges = Vec::new();

    if let Some(key) = params.and_then(|p| p.key.as_deref()) {
        // Extract specific header by name
        for header in message.headers_with_name(key) {
            append_header_ranges(&mut ranges, header, hide_key, hide_value);
        }
    } else {
        // Extract all headers
        for header in message.headers() {
            append_header_ranges(&mut ranges, header, hide_key, hide_value);
        }
    }

    Ok(ranges)
}

fn append_header_ranges<S: Store>(
    ranges: &mut Vec<Range<usize>>,
    header: &Header<S>,
    hide_key: bool,
    hide_value: bool,
) {
    if hide_key {
        // Reveal only the value
        ranges.extend(rangeset_to_vec(header.value.indices()));
    } else if hide_value {
        // Reveal header excluding the value
        let without_value = header.without_value();
        ranges.extend(rangeset_to_vec(without_value.indices()));
    } else {
        // Reveal entire header
        ranges.extend(rangeset_to_vec(header.indices()));
    }
}

fn extract_body<S: Store>(
    handler: &Handler,
    message: &HttpMessage<'_, S>,
) -> Result<Vec<Range<usize>>> {
    let body = match message.body() {
        Some(body) => body,
        None => return Ok(Vec::new()),
    };

    let params = handler.params.as_ref();

    // No params: return entire body
    if params.is_none() {
        return Ok(rangeset_to_vec(body.indices()));
    }

    let params = params.unwrap();

    match params.content_type.as_deref() {
        Some("json") => extract_json_body(params, body),
        _ => {
            // No recognized content_type: return entire body
            Ok(rangeset_to_vec(body.indices()))
        }
    }
}

fn extract_json_body<S: Store>(
    params: &HandlerParams,
    body: &Body<S>,
) -> Result<Vec<Range<usize>>> {
    let doc = match &body.content {
        BodyContent::Json(doc) => doc,
        _ => return Err(SdkError::handler("body is not JSON")),
    };

    let path = params
        .path
        .as_deref()
        .ok_or_else(|| SdkError::handler("JSON handler requires a 'path' parameter"))?;

    let hide_key = params.hide_key.unwrap_or(false);
    let hide_value = params.hide_value.unwrap_or(false);

    if hide_key && hide_value {
        return Err(SdkError::handler("cannot hide both key and value"));
    }

    // For hideKey/hideValue, we need the parent object's key-value pair.
    // Otherwise we just need the value itself.
    if (hide_key || hide_value)
        && let Some((parent_path, key)) = split_json_path(path)
    {
        let parent: Option<&JsonValue<S>> = if parent_path.is_empty() {
            Some(&doc.root)
        } else {
            doc.get(parent_path)
        };

        if let Some(JsonValue::Object(obj)) = parent
            && let Some(kv) = obj.elems.iter().find(|kv| kv.key == key)
        {
            return extract_kv_ranges(kv, hide_key, hide_value);
        }
        // If parent is an array, ignore hideKey/hideValue — return value
        // only
    }

    // Return the value's ranges directly (full key-value pair for objects, or just
    // the value).
    let value = doc
        .get(path)
        .ok_or_else(|| SdkError::handler(format!("JSON path '{path}' not found")))?;

    // If no hide options and this is an object field, return the whole key-value
    // pair.
    if !hide_key
        && !hide_value
        && let Some((parent_path, key)) = split_json_path(path)
    {
        let parent: Option<&JsonValue<S>> = if parent_path.is_empty() {
            Some(&doc.root)
        } else {
            doc.get(parent_path)
        };

        if let Some(JsonValue::Object(obj)) = parent
            && let Some(kv) = obj.elems.iter().find(|kv| kv.key == key)
        {
            return Ok(rangeset_to_vec(kv.view().indices()));
        }
    }

    Ok(rangeset_to_vec(value.view().indices()))
}

/// Extracts ranges from a JSON key-value pair with hide options.
fn extract_kv_ranges<S: Store>(
    kv: &KeyValue<S>,
    hide_key: bool,
    hide_value: bool,
) -> Result<Vec<Range<usize>>> {
    if hide_key {
        // Reveal only the value
        Ok(rangeset_to_vec(kv.value.view().indices()))
    } else if hide_value {
        // Reveal the key-value pair excluding the value
        let without_value = kv.without_value();
        Ok(rangeset_to_vec(without_value.indices()))
    } else {
        // Reveal entire key-value pair
        Ok(rangeset_to_vec(kv.view().indices()))
    }
}

/// Splits a JSON path into (parent_path, leaf_key).
///
/// Examples:
/// - `"name"` -> `Some(("", "name"))`
/// - `"user.name"` -> `Some(("user", "name"))`
/// - `"user.profile.name"` -> `Some(("user.profile", "name"))`
/// - `"arr.0"` -> `Some(("arr", "0"))`
fn split_json_path(path: &str) -> Option<(&str, &str)> {
    if path.is_empty() {
        return None;
    }
    match path.rfind('.') {
        Some(pos) => Some((&path[..pos], &path[pos + 1..])),
        None => Some(("", path)),
    }
}

fn extract_all(handler: &Handler, raw: &[u8]) -> Result<Vec<Range<usize>>> {
    let params = handler.params.as_ref();

    if let Some(params) = params
        && params.content_type.as_deref() == Some("regex")
        && let Some(pattern) = params.regex.as_deref()
    {
        return extract_regex(raw, pattern);
    }

    // Return entire transcript as a single range.
    #[allow(clippy::single_range_in_vec_init)]
    Ok(vec![0..raw.len()])
}

fn extract_regex(raw: &[u8], pattern: &str) -> Result<Vec<Range<usize>>> {
    let re = regex::bytes::Regex::new(pattern)
        .map_err(|e| SdkError::handler(format!("invalid regex '{pattern}': {e}")))?;

    let ranges: Vec<Range<usize>> = re.find_iter(raw).map(|m| m.start()..m.end()).collect();

    Ok(ranges)
}
