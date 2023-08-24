//! Some support for redacting json using e.g. pest
use std::ops::Range;

use pest::{iterators::Pairs, Parser};

pub struct JsonSpanner<'a> {
    matches: Vec<Match>,
    pairs: Pairs<'a, crate::span::json::Rule>,
}

#[derive(pest_derive::Parser)]
#[grammar = "span/json/json.pest"]
struct JsonParser;

impl<'a> JsonSpanner<'a> {
    pub fn new(input: &'a str) -> Self {
        let pairs = JsonParser::parse(Rule::json, input).unwrap();
        Self {
            pairs,
            matches: vec![],
        }
    }

    pub fn add_match(
        &mut self,
        rule: JsonRule,
        marker: fn(&str) -> bool,
        nth: Option<usize>,
    ) -> &mut Self {
        self.matches.push(Match {
            rule,
            marker,
            nth: nth.unwrap_or_default(),
        });

        self
    }

    pub fn span_json(&self) -> Vec<Range<usize>> {
        // Iterate over json and apply matches. If marker returns true then add range for
        // commitment
        todo!()
    }
}

pub struct Match {
    rule: JsonRule,
    marker: fn(&str) -> bool,
    nth: usize,
}

pub enum JsonRule {
    Object,
    Pair,
    Array,
    String,
    Number,
    Bool,
    Null,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pest::Parser;

    #[test]
    fn test_json_spanner() {
        let test_json =
            r#"{"foo": "bar", "baz": 123, "quux": { "a": "b", "c": "d" }, "arr": [1, 2, 3]}"#;

        let pairs = JsonParser::parse(Rule::json, test_json).unwrap_or_else(|e| panic!("{}", e));
        println!("{:#?}", pairs);
    }
}
