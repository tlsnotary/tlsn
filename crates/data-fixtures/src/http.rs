//! HTTP data fixtures

/// HTTP requests
pub mod request {
    use crate::define_fixture;

    define_fixture!(
        GET_EMPTY,
        "A GET request without a body or headers.",
        "../data/http/request_get_empty"
    );
    define_fixture!(
        GET_EMPTY_HEADER,
        "A GET request with an empty header.",
        "../data/http/request_get_empty_header"
    );
    define_fixture!(
        GET_WITH_HEADER,
        "A GET request with a header.",
        "../data/http/request_get_with_header"
    );
    define_fixture!(
        POST_JSON,
        "A POST request with a JSON body.",
        "../data/http/request_post_json"
    );
}

/// HTTP responses
pub mod response {
    use crate::define_fixture;

    define_fixture!(
        OK_EMPTY,
        "An OK response without a body.",
        "../data/http/response_empty"
    );
    define_fixture!(
        OK_EMPTY_HEADER,
        "An OK response with an empty header.",
        "../data/http/response_empty"
    );
    define_fixture!(
        OK_TEXT,
        "An OK response with a text body.",
        "../data/http/response_text"
    );
    define_fixture!(
        OK_JSON,
        "An OK response with a JSON body.",
        "../data/http/response_json"
    );
    define_fixture!(
        OK_CHUNKED_TEXT,
        "An OK response with chunked transfer encoding and text body.",
        "../data/http/response_chunked_text"
    );
    define_fixture!(
        OK_CHUNKED_JSON,
        "An OK response with chunked transfer encoding and JSON body.",
        "../data/http/response_chunked_json"
    );
    define_fixture!(
        OK_CHUNKED_TEXT_MULTI,
        "An OK response with chunked transfer encoding and text body split across multiple chunks.",
        "../data/http/response_chunked_text_multi"
    );
    define_fixture!(
        OK_CHUNKED_JSON_MULTI,
        "An OK response with chunked transfer encoding and JSON body split across multiple chunks.",
        "../data/http/response_chunked_json_multi"
    );
}
