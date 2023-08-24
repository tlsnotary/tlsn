//! Some support for redacting json using e.g. pest

#[derive(pest_derive::Parser)]
#[grammar = "span/json/json.pest"]
struct JsonSpanner;

enum JSONValue<'a> {
    Object(Vec<(&'a str, JSONValue<'a>)>),
    Array(Vec<JSONValue<'a>>),
    String(&'a str),
    Number(f64),
    Boolean(bool),
    Null,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pest::Parser;

    struct JsonOuter {
        foo: String,
        baz: i32,
        quux: JsonInner,
    }

    struct JsonInner {
        a: String,
        b: String,
    }

    #[test]
    fn test_json_spanner() {
        let test_json =
            r#"{"foo": "bar", "baz": 123, "quux": { "a": "b", "c": "d" }, "arr": [1, 2, 3]}"#;

        let mut pairs =
            JsonSpanner::parse(Rule::json, test_json).unwrap_or_else(|e| panic!("{}", e));
        println!("{:#?}", pairs);
    }
}
