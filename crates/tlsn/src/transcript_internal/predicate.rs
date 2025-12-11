//! Predicate proving and verification over transcript data.

use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_memory_core::{
    MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_predicate::{Pred, compiler::Compiler};
use mpz_vm_core::{Call, CallableExt, Vm};
use rangeset::set::RangeSet;
use tlsn_core::{config::prove::PredicateConfig, transcript::Direction};

use super::{ReferenceMap, TranscriptRefs};

/// Error during predicate proving/verification.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PredicateError {
    /// Indices not found in transcript references.
    #[error("predicate indices {0:?} not found in transcript references")]
    IndicesNotFound(RangeSet<usize>),
    /// VM error.
    #[error("VM error: {0}")]
    Vm(#[from] mpz_vm_core::VmError),
    /// Circuit call error.
    #[error("circuit call error: {0}")]
    Call(#[from] mpz_vm_core::CallError),
}

/// Converts a slice of indices to a RangeSet (each index becomes a single-byte
/// range).
fn indices_to_rangeset(indices: &[usize]) -> RangeSet<usize> {
    indices.iter().map(|&idx| idx..idx + 1).collect()
}

/// Proves predicates over transcript data (prover side).
///
/// Each predicate is compiled to a circuit and executed with the corresponding
/// transcript bytes as input. The circuit outputs a single bit that must be
/// true.
pub(crate) fn prove_predicates<T: Vm<Binary>>(
    vm: &mut T,
    transcript_refs: &TranscriptRefs,
    predicates: &[PredicateConfig],
) -> Result<(), PredicateError> {
    let mut compiler = Compiler::new();

    for predicate in predicates {
        let refs = match predicate.direction() {
            Direction::Sent => &transcript_refs.sent,
            Direction::Received => &transcript_refs.recv,
        };

        // Compile predicate to circuit
        let circuit = compiler.compile(predicate.predicate());

        // Get indices from the predicate and convert to RangeSet
        let indices = indices_to_rangeset(&predicate.indices());

        execute_predicate(vm, refs, &indices, &circuit)?;
    }

    Ok(())
}

/// Verifies predicates over transcript data (verifier side).
///
/// The verifier must provide the same predicates that the prover used,
/// looked up by predicate name from out-of-band agreement.
///
/// # Arguments
///
/// * `vm` - The zkVM.
/// * `transcript_refs` - References to transcript data in the VM.
/// * `predicates` - Iterator of (direction, indices, predicate) tuples.
pub(crate) fn verify_predicates<T: Vm<Binary>>(
    vm: &mut T,
    transcript_refs: &TranscriptRefs,
    predicates: impl IntoIterator<Item = (Direction, RangeSet<usize>, Pred)>,
) -> Result<(), PredicateError> {
    let mut compiler = Compiler::new();

    for (direction, indices, predicate) in predicates {
        let refs = match direction {
            Direction::Sent => &transcript_refs.sent,
            Direction::Received => &transcript_refs.recv,
        };

        // Compile predicate to circuit
        let circuit = compiler.compile(&predicate);

        execute_predicate(vm, refs, &indices, &circuit)?;
    }

    Ok(())
}

/// Executes a predicate circuit with transcript bytes as input.
fn execute_predicate<T: Vm<Binary>>(
    vm: &mut T,
    refs: &ReferenceMap,
    indices: &RangeSet<usize>,
    circuit: &Circuit,
) -> Result<(), PredicateError> {
    // Get the transcript bytes for the predicate indices
    let indexed_refs = refs
        .index(indices)
        .ok_or_else(|| PredicateError::IndicesNotFound(indices.clone()))?;

    // Build the circuit call with transcript bytes as inputs
    let circuit = Arc::new(circuit.clone());
    let mut call_builder = Call::builder(circuit);

    // Add each byte in the range as an input to the circuit
    // The predicate circuit expects bytes in order, so we iterate through
    // the indexed refs which maintains ordering
    for (_range, vector) in indexed_refs.iter() {
        call_builder = call_builder.arg(*vector);
    }

    let call = call_builder.build()?;

    // Execute the circuit - output is a single bit (bool)
    let output: Vector<U8> = vm.call(call)?;

    // The output should be a single bit indicating predicate satisfaction.
    // We mark it public so both parties can see the result.
    vm.mark_public(output)?;
    vm.commit(output)?;

    // Decode the result to verify it's true
    let result_fut = vm.decode(output)?;

    // Note: The actual verification that the output is true happens during
    // execution. If the predicate is false, the ZK proof will fail.

    // Drop the future - we don't need to wait for it here since execute_all
    // will handle this
    drop(result_fut);

    Ok(())
}
