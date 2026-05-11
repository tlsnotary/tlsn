# Examples

This folder contains examples demonstrating how to use the TLSNotary protocol.

* [Basic](./basic/README.md): Basic Prover and Verifier session.
* [Attestation](./attestation/README.md): Issuing an attestation where a Verifier acts as a Notary.
* [Basic_zk](../examples-zk/README.md): Basic Prover and Verifier session demonstrating zero-knowledge age verification using Noir. Lives in its own crate (`crates/examples-zk`) outside the workspace so the heavy `noir-rs` git dependency does not slow down builds of the rest of the project.


Refer to <https://tlsnotary.org/docs/quick_start> for a quick start guide to using TLSNotary with these examples.
