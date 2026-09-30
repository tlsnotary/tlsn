//! Strict deserialization for the wasm ABI boundary.
//!
//! `serde-wasm-bindgen` deserializes a JS object into a struct by looking up
//! only the fields declared on that struct, so any *extra* property is silently
//! dropped. `#[serde(deny_unknown_fields)]` does not help here: it never sees
//! those keys because serde-wasm-bindgen never feeds them to the visitor
//! (<https://github.com/RReverser/serde-wasm-bindgen/issues/39>).
//!
//! [`Strict`] works around this by adding a `#[serde(flatten)]` catch-all map,
//! which forces serde to switch from struct-field lookup to map iteration, so
//! unknown keys become observable and can be rejected.

use std::collections::HashMap;

use serde::{
    Deserialize,
    de::{DeserializeOwned, Error as _, IgnoredAny},
};
use wasm_bindgen::JsValue;

#[derive(Deserialize)]
struct Wrap<T> {
    #[serde(flatten)]
    result: T,
    #[serde(flatten)]
    extra_fields: HashMap<String, IgnoredAny>,
}

/// A `Deserialize` wrapper that rejects unknown fields.
///
/// This is the underlying building block for [`from_wasm_strict`]. It can also
/// be used on nested fields, e.g.
/// `#[serde(deserialize_with = "...")]`, so that objects nested inside a config
/// are checked too.
pub(crate) struct Strict<T>(pub(crate) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Strict<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let Wrap {
            result,
            extra_fields,
        } = Wrap::<T>::deserialize(deserializer)?;

        if !extra_fields.is_empty() {
            let mut keys: Vec<&str> = extra_fields.keys().map(String::as_str).collect();
            keys.sort_unstable();
            return Err(D::Error::custom(format!(
                "unknown field(s): {}",
                keys.join(", ")
            )));
        }

        Ok(Strict(result))
    }
}

/// Deserializes `value` into `T`, rejecting any property not declared on `T`.
///
/// Deserialization happens here inside the function body rather than at the
/// wasm-bindgen ABI boundary (see [`Ts`](tsify::Ts)), so a failure is a normal
/// `Result` instead of a `wasm_bindgen::throw_str` that skips destructors.
pub(crate) fn from_wasm_strict<T>(value: JsValue) -> Result<T, serde_wasm_bindgen::Error>
where
    T: DeserializeOwned,
{
    serde_wasm_bindgen::from_value::<Strict<T>>(value).map(|strict| strict.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::ProverConfig;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    fn valid_prover_config() -> JsValue {
        let obj = js_sys::Object::new();
        let set = |key: &str, value: JsValue| {
            js_sys::Reflect::set(&obj, &key.into(), &value).unwrap();
        };

        set("server_name", "example.com".into());
        set("mode", "Mpc".into());
        set("max_sent_data", 1024u32.into());
        set("max_recv_data", 2048u32.into());
        set("network", "Bandwidth".into());

        obj.into()
    }

    #[wasm_bindgen_test]
    fn accepts_declared_fields() {
        let config = from_wasm_strict::<ProverConfig>(valid_prover_config()).unwrap();

        assert_eq!(config.server_name, "example.com");
        assert_eq!(config.max_sent_data, 1024);
        assert_eq!(config.max_recv_data, 2048);
    }

    #[wasm_bindgen_test]
    fn applies_optional_fields() {
        let value = valid_prover_config();
        let obj = value.unchecked_ref::<js_sys::Object>();
        js_sys::Reflect::set(obj, &"max_sent_records".into(), &7u32.into()).unwrap();

        let config = from_wasm_strict::<ProverConfig>(value).unwrap();
        assert_eq!(config.max_sent_records, Some(7));
    }

    #[wasm_bindgen_test]
    fn rejects_misspelled_field() {
        let value = valid_prover_config();
        let obj = value.unchecked_ref::<js_sys::Object>();
        js_sys::Reflect::set(obj, &"max_sent_recods".into(), &7u32.into()).unwrap();

        let err = from_wasm_strict::<ProverConfig>(value).unwrap_err();
        assert!(
            err.to_string().contains("max_sent_recods"),
            "unexpected error: {err}"
        );
    }

    #[wasm_bindgen_test]
    fn rejects_camel_case_alias() {
        let value = valid_prover_config();
        let obj = value.unchecked_ref::<js_sys::Object>();
        js_sys::Reflect::set(obj, &"maxSentData".into(), &7u32.into()).unwrap();

        assert!(from_wasm_strict::<ProverConfig>(value).is_err());
    }

    #[wasm_bindgen_test]
    fn rejects_field_at_wrong_level() {
        // A nested-only option passed at the top level must not be ignored.
        let value = valid_prover_config();
        let obj = value.unchecked_ref::<js_sys::Object>();
        js_sys::Reflect::set(obj, &"max_num_streams".into(), &4096u32.into()).unwrap();

        let err = from_wasm_strict::<ProverConfig>(value).unwrap_err();
        assert!(
            err.to_string().contains("max_num_streams"),
            "unexpected error: {err}"
        );
    }
}
