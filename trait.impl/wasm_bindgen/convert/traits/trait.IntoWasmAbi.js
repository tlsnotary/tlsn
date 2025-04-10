(function() {
    var implementors = Object.fromEntries([["tlsn_wasm",[["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"enum\" href=\"tlsn_wasm/types/enum.TlsVersion.html\" title=\"enum tlsn_wasm::types::TlsVersion\">TlsVersion</a><div class=\"where\">where\n    <a class=\"enum\" href=\"tlsn_wasm/types/enum.TlsVersion.html\" title=\"enum tlsn_wasm::types::TlsVersion\">TlsVersion</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/prover/struct.JsProver.html\" title=\"struct tlsn_wasm::prover::JsProver\">JsProver</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Attestation.html\" title=\"struct tlsn_wasm::types::Attestation\">Attestation</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.ConnectionInfo.html\" title=\"struct tlsn_wasm::types::ConnectionInfo\">ConnectionInfo</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.ConnectionInfo.html\" title=\"struct tlsn_wasm::types::ConnectionInfo\">ConnectionInfo</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.HttpResponse.html\" title=\"struct tlsn_wasm::types::HttpResponse\">HttpResponse</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.HttpResponse.html\" title=\"struct tlsn_wasm::types::HttpResponse\">HttpResponse</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.NotarizationOutput.html\" title=\"struct tlsn_wasm::types::NotarizationOutput\">NotarizationOutput</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.PartialTranscript.html\" title=\"struct tlsn_wasm::types::PartialTranscript\">PartialTranscript</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.PartialTranscript.html\" title=\"struct tlsn_wasm::types::PartialTranscript\">PartialTranscript</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Presentation.html\" title=\"struct tlsn_wasm::types::Presentation\">Presentation</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.PresentationOutput.html\" title=\"struct tlsn_wasm::types::PresentationOutput\">PresentationOutput</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.PresentationOutput.html\" title=\"struct tlsn_wasm::types::PresentationOutput\">PresentationOutput</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Secrets.html\" title=\"struct tlsn_wasm::types::Secrets\">Secrets</a>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.Transcript.html\" title=\"struct tlsn_wasm::types::Transcript\">Transcript</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.Transcript.html\" title=\"struct tlsn_wasm::types::Transcript\">Transcript</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.TranscriptLength.html\" title=\"struct tlsn_wasm::types::TranscriptLength\">TranscriptLength</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.TranscriptLength.html\" title=\"struct tlsn_wasm::types::TranscriptLength\">TranscriptLength</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.VerifierOutput.html\" title=\"struct tlsn_wasm::types::VerifierOutput\">VerifierOutput</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.VerifierOutput.html\" title=\"struct tlsn_wasm::types::VerifierOutput\">VerifierOutput</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/types/struct.VerifyingKey.html\" title=\"struct tlsn_wasm::types::VerifyingKey\">VerifyingKey</a><div class=\"where\">where\n    <a class=\"struct\" href=\"tlsn_wasm/types/struct.VerifyingKey.html\" title=\"struct tlsn_wasm::types::VerifyingKey\">VerifyingKey</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.219/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div>"],["impl <a class=\"trait\" href=\"https://docs.rs/wasm-bindgen/0.2/wasm_bindgen/convert/traits/trait.IntoWasmAbi.html\" title=\"trait wasm_bindgen::convert::traits::IntoWasmAbi\">IntoWasmAbi</a> for <a class=\"struct\" href=\"tlsn_wasm/verifier/struct.JsVerifier.html\" title=\"struct tlsn_wasm::verifier::JsVerifier\">JsVerifier</a>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[7943]}