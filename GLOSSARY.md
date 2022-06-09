# TLSNotary Glossary
The protocol consists of 2 major phases, `Notarization` and `Revelation`. Both phases have terms which refer to the same entities, and thus the context in which they are used must be explicit.

---
## **`Notarization`** 
The phase during which `Prover` and `Notary` coordinate to execute a `Session` with `Server` to produce a `Note`.

| Term| Description|
| ------------- |-------------|
| `Prover` | An entity which has `Request(s)` and wants to be able to prove particular `Response(s)` are returned when processed by the `Server` |
| `Notary` | An entity which coordinates with `Prover` to execute a `Session` with `Server`, and subsequently constructs and signs a `Note`. |
| `Server` | An entity which supports TLS and hosts an application which accepts `Request(s)` and returns corresponding `Response(s)` |
| `Client` | An entity which operates the connection with `Server` during `Session`, forwarding TLS records jointly constructed by `Prover` and `Notary`. |
| `Request` | An application data payload sent by `Prover` to `Server`. |
| `Response` | An application data payload returned by `Server` in response to a `Request`. |
| `Session` | The three-party TLS session executed by the `Prover` and `Notary` with the `Server`. |
| `Note` | The document output by the `Notarization` phase containing information such as signed commitments corresponding to the contents of the `Session`. |
---
## **`Revelation`**
The phase during which `Prover` convinces `Verifier` of statements regarding the content of `Request(s)` and `Response(s)` in the `Session` attested to by a `Note`.

| Term| Description|
| ------------- |-------------|
| `Prover` | An entity which has a `Note` signed by a `Notary` which corresponds to a `Session` and would like to convince `Verifier` of statements pertaining to it. |
| `Verifier` | An entity which trusts `Notary`, validates the `Note`, and verifies statements made by the `Prover`. |
