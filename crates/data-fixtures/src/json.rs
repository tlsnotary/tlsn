//! JSON data fixtures

use crate::define_fixture;

define_fixture!(
    ARRAY,
    "A JSON array.",
    "../data/json/array"
);

define_fixture!(
    INTEGER,
    "A JSON integer.",
    "../data/json/integer"
);

define_fixture!(
    NESTED_OBJECT,
    "A nested JSON object.",
    "../data/json/nested_object"
);

define_fixture!(
    VALUES,
    "A JSON object with various values.",
    "../data/json/values"
);
