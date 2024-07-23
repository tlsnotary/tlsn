use std::error::Error;

use spansy::{json::KeyValue, Spanned};
use tlsn_core::{commitment::TranscriptCommitmentBuilder, Direction};

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
        builder: &mut TranscriptCommitmentBuilder,
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
    /// The default implementation commits the object without any of the key-value pairs, then
    /// commits each key-value pair individually.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `object` - The JSON object to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_object(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
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
    /// The default implementation commits the pair without the value, and then commits the value
    /// separately.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `kv` - The JSON key-value pair to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_key_value(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
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
    /// The default implementation commits to the entire array, then commits the array
    /// excluding all values and separators.
    ///
    /// # Arguments
    ///
    /// * `builder` - The commitment builder.
    /// * `array` - The JSON array to commit.
    /// * `direction` - The direction of the data (sent or received).
    fn commit_array(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        array: &Array,
        direction: Direction,
    ) -> Result<(), JsonCommitError> {
        builder
            .commit(array, direction)
            .map_err(|e| JsonCommitError::new_with_source("failed to commit array", e))?;

        if !array.elems.is_empty() {
            builder
                .commit(&array.without_values(), direction)
                .map_err(|e| {
                    JsonCommitError::new_with_source("failed to commit array excluding values", e)
                })?;
        }

        // TODO: Commit each value separately, but we need a strategy for handling
        // separators.

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
        builder: &mut TranscriptCommitmentBuilder,
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
        builder: &mut TranscriptCommitmentBuilder,
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
        builder: &mut TranscriptCommitmentBuilder,
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
        builder: &mut TranscriptCommitmentBuilder,
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
