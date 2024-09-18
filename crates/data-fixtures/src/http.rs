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
}
