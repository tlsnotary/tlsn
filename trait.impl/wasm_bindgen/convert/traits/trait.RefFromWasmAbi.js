(function() {
    var implementors = Object.fromEntries([["tlsn_wasm",[["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"enum\" href=\"tlsn_wasm/enum.LoggingLevel.html\" title=\"enum tlsn_wasm::LoggingLevel\">LoggingLevel</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"enum\" href=\"tlsn_wasm/types/enum.Body.html\" title=\"enum tlsn_wasm::types::Body\">Body</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"enum\" href=\"tlsn_wasm/types/enum.KeyType.html\" title=\"enum tlsn_wasm::types::KeyType\">KeyType</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"enum\" href=\"tlsn_wasm/types/enum.Method.html\" title=\"enum tlsn_wasm::types::Method\">Method</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/prover/struct.JsProver.html\" title=\"struct tlsn_wasm::prover::JsProver\">JsProver</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/prover/struct.ProverConfig.html\" title=\"struct tlsn_wasm::prover::ProverConfig\">ProverConfig</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/struct.LoggingConfig.html\" title=\"struct tlsn_wasm::LoggingConfig\">LoggingConfig</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Attestation.html\" title=\"struct tlsn_wasm::types::Attestation\">Attestation</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Commit.html\" title=\"struct tlsn_wasm::types::Commit\">Commit</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.HttpRequest.html\" title=\"struct tlsn_wasm::types::HttpRequest\">HttpRequest</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.NotarizationOutput.html\" title=\"struct tlsn_wasm::types::NotarizationOutput\">NotarizationOutput</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Presentation.html\" title=\"struct tlsn_wasm::types::Presentation\">Presentation</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Reveal.html\" title=\"struct tlsn_wasm::types::Reveal\">Reveal</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Secrets.html\" title=\"struct tlsn_wasm::types::Secrets\">Secrets</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/verifier/struct.JsVerifier.html\" title=\"struct tlsn_wasm::verifier::JsVerifier\">JsVerifier</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.RefFromWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::RefFromWasmAbi\">RefFromWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/verifier/struct.VerifierConfig.html\" title=\"struct tlsn_wasm::verifier::VerifierConfig\">VerifierConfig</a><div class=\"where\">where\n    Self: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,</div>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[7420]}