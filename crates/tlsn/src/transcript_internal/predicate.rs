//! Predicate proving and verification over transcript data.

use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    DecodeFutureTyped, MemoryExt,
    binary::{Binary, Bool},
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
    /// Decode error.
    #[error("decode error: {0}")]
    Decode(#[from] mpz_memory_core::DecodeError),
    /// Missing decoding.
    #[error("missing decoding")]
    MissingDecoding,
    /// Predicate not satisfied.
    #[error("predicate evaluated to false")]
    PredicateNotSatisfied,
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

        // Prover doesn't need to verify output - they know their data satisfies the predicate
        let _ = execute_predicate(vm, refs, &indices, &circuit)?;
    }

    Ok(())
}

/// Proof that predicates were satisfied.
///
/// Must be verified after `vm.execute_all()` completes.
#[must_use]
pub(crate) struct PredicateProof {
    /// Decode futures for each predicate output.
    outputs: Vec<DecodeFutureTyped<BitVec, bool>>,
}

impl PredicateProof {
    /// Verifies that all predicates evaluated to true.
    ///
    /// Must be called after `vm.execute_all()` completes.
    pub(crate) fn verify(self) -> Result<(), PredicateError> {
        for mut output in self.outputs {
            let result = output
                .try_recv()
                .map_err(PredicateError::Decode)?
                .ok_or(PredicateError::MissingDecoding)?;

            if !result {
                return Err(PredicateError::PredicateNotSatisfied);
            }
        }
        Ok(())
    }
}

/// Verifies predicates over transcript data (verifier side).
///
/// The verifier must provide the same predicates that the prover used,
/// looked up by predicate name from out-of-band agreement.
///
/// Returns a [`PredicateProof`] that must be verified after `vm.execute_all()`.
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
) -> Result<PredicateProof, PredicateError> {
    let mut compiler = Compiler::new();
    let mut outputs = Vec::new();

    for (direction, indices, predicate) in predicates {
        let refs = match direction {
            Direction::Sent => &transcript_refs.sent,
            Direction::Received => &transcript_refs.recv,
        };

        // Compile predicate to circuit
        let circuit = compiler.compile(&predicate);

        let output_fut = execute_predicate(vm, refs, &indices, &circuit)?;
        outputs.push(output_fut);
    }

    Ok(PredicateProof { outputs })
}

/// Executes a predicate circuit with transcript bytes as input.
///
/// Returns a decode future for the circuit output.
fn execute_predicate<T: Vm<Binary>>(
    vm: &mut T,
    refs: &ReferenceMap,
    indices: &RangeSet<usize>,
    circuit: &Circuit,
) -> Result<DecodeFutureTyped<BitVec, bool>, PredicateError> {
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

    // Execute the circuit - output is a single bit (true/false)
    // Both parties must call decode() on the output to reveal it
    let output: Bool = vm.call(call)?;

    // Return decode future - caller must verify output == true after execute_all
    Ok(vm.decode(output)?)
}
