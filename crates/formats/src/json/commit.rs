use std::error::Error;

use rangeset::{Difference, RangeSet, ToRangeSet};
use spansy::{json::KeyValue, Spanned};
use tlsn_core::transcript::{Direction, TranscriptCommitConfigBuilder};

use crate::json::{Array, Bool, JsonValue, Null, Number, Object, String as JsonString};

/// JSON commitment error.
#[derive(Debug, thiserror::Error)]
#[error("json commitment error: {msg}")]
pub struct JsonCommitError {
    msg: String,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl JsonCommitError {
    /// Creates a new JSON commitment error.
    ///
    /// # Arguments
    ///
    /// * `msg` - The error message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            msg: msg.into(),
            source: None,
        }
    }

    /// Creates a new JSON commitment error with a source.
    ///
    /// # Arguments
    ///
    /// * `msg` - The error message.
    /// * `source` - The source error.
    pub fn new_with_source<E>(msg: impl Into<String>, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            msg: msg.into(),
            source: Some(source.into()),
        }
    }

    /// Returns the error message.
    pub fn msg(&self) -> &str {
        &self.msg
    }
}

/// A JSON committer.
pub trait JsonCommit {
    /// Commits to a JSON value.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `value` - The JSON value to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_value(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        value: &JsonValue,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        match value {
            JsonValue::Object(obj) => self.commit_object(builder, obj, direction),
            JsonValue::Array(arr) => self.commit_array(builder, arr, direction),
            JsonValue::String(string) => self.commit_string(builder, string, direction),
            JsonValue::Number(number) => self.commit_number(builder, number, direction),
            JsonValue::Bool(boolean) => self.commit_bool(builder, boolean, direction),
            JsonValue::Null(null) => self.commit_null(builder, null, direction),
        }
    }

    /// Commits to a JSON object.
    ///
    /// The default implementation commits the object without any of the
    /// key-value pairs, then commits each key-value pair individually.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `object` - The JSON object to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_object(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        object: &Object,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(&object.without_pairs(), direction)
            .map_err(|e| JsonCommitError::new_with_source("failed to commit object", e))?;

        for kv in &object.elems {
            self.commit_key_value(builder, kv, direction)?;
        }

        Ok(())
    }

    /// Commits to a JSON key-value pair.
    ///
    /// The default implementation commits the pair without the value, and then
    /// commits the value separately.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `kv` - The JSON key-value pair to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_key_value(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        kv: &KeyValue,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(&kv.without_value(), direction)
            .map_err(|e| {
                JsonCommitError::new_with_source(
                    "failed to commit key-value pair excluding the value",
                    e,
                )
            })?;

        self.commit_value(builder, &kv.value, direction)
    }

    /// Commits to a JSON array.
    ///
    /// The default implementation commits to the entire array, then commits the
    /// array excluding all values and separators.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `array` - The JSON array to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_array(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        array: &Array,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(array, direction)
            .map_err(|e| JsonCommitError::new_with_source("failed to commit array", e))?;

        if !array.elems.is_empty() {
            let without_values = array.without_values();

            // Commit to the array excluding all values and separators.
            builder.commit(&without_values, direction).map_err(|e| {
                JsonCommitError::new_with_source("failed to commit array excluding values", e)
            })?;

            // Commit to the separators and whitespace of the array
            let array_range: RangeSet<usize> = array.to_range_set().difference(&without_values);
            let difference = array
                .elems
                .iter()
                .map(|e| e.to_range_set())
                .fold(array_range.clone(), |acc, range| acc.difference(&range));

            for range in difference.iter_ranges() {
                builder.commit(&range, direction).map_err(|e| {
                    JsonCommitError::new_with_source("failed to commit array element", e)
                })?;
            }

            // Commit to the values of the array
            for elem in &array.elems {
                self.commit_value(builder, elem, direction)?;
            }
        }

        Ok(())
    }

    /// Commits to a JSON string.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `string` - The JSON string to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_string(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        string: &JsonString,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        // Skip empty strings.
        if string.span().is_empty() {
            return Ok(());
        }

        builder
            .commit(string, direction)
            .map(|_| ())
            .map_err(|e| JsonCommitError::new_with_source("failed to commit string", e))
    }

    /// Commits to a JSON number.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `number` - The JSON number to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_number(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        number: &Number,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(number, direction)
            .map(|_| ())
            .map_err(|e| JsonCommitError::new_with_source("failed to commit number", e))
    }

    /// Commits to a JSON boolean value.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `boolean` - The JSON boolean to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_bool(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        boolean: &Bool,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(boolean, direction)
            .map(|_| ())
            .map_err(|e| JsonCommitError::new_with_source("failed to commit boolean", e))
    }

    /// Commits to a JSON null value.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `null` - The JSON null to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_null(
        &mut self,
        builder: &mut TranscriptCommitConfigBuilder,
        null: &Null,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(null, direction)
            .map(|_| ())
            .map_err(|e| JsonCommitError::new_with_source("failed to commit null", e))
    }
}

/// Default committer for JSON values.
#[derive(Debug, Default, Clone)]
pub struct DefaultJsonCommitter {}

impl JsonCommit for DefaultJsonCommitter {}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use spansy::json::parse_slice;
    use tlsn_core::transcript::Transcript;
    use tlsn_data_fixtures::json as fixtures;

    #[rstest]
    #[case::array(fixtures::ARRAY)]
    #[case::integer(fixtures::INTEGER)]
    #[case::json_object(fixtures::NESTED_OBJECT)]
    #[case::values(fixtures::VALUES)]
    fn test_json_commit(#[case] src: &'static [u8]) {
        let transcript = Transcript::new([], src);
        let json_data = parse_slice(src).unwrap();
        let mut committer = DefaultJsonCommitter::default();
        let mut builder = TranscriptCommitConfigBuilder::new(&transcript);

        committer
            .commit_value(&mut builder, &json_data, Direction::Received)
            .unwrap();

        builder.build().unwrap();
    }
}
