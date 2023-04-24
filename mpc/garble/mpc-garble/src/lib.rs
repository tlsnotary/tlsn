//! This crate provides an implementation of garbled circuit protocols to facilitate MPC.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;

use mpc_circuits::{
    types::{StaticValueType, Value},
    Circuit,
};

pub mod config;
pub(crate) mod evaluator;
pub(crate) mod generator;
pub mod ot;
pub mod protocol;
pub(crate) mod registry;
mod threadpool;

pub use evaluator::{Evaluator, EvaluatorConfig, EvaluatorConfigBuilder, EvaluatorError};
pub use generator::{Generator, GeneratorConfig, GeneratorConfigBuilder, GeneratorError};
pub use registry::{ValueId, ValueRef};
pub use threadpool::ThreadPool;

use utils::id::NestedId;

/// Errors that can occur when using an implementation of [`Vm`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VmError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    ExecutionError(#[from] ExecutionError),
    #[error(transparent)]
    ProveError(#[from] ProveError),
    #[error(transparent)]
    VerifyError(#[from] VerifyError),
    #[error(transparent)]
    DecodeError(#[from] DecodeError),
    #[error("thread already exists: {0}")]
    ThreadAlreadyExists(String),
    #[error("vm is shutdown")]
    Shutdown,
}

/// Errors that can occur when interacting with memory.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum MemoryError {
    #[error("duplicate value id: {0:?}")]
    DuplicateValueId(ValueId),
    #[error("duplicate value: {0:?}")]
    DuplicateValue(ValueRef),
    #[error(transparent)]
    TypeError(#[from] mpc_circuits::types::TypeError),
    #[error("invalid value type {1:?} for {0:?}")]
    InvalidType(ValueId, mpc_circuits::types::ValueType),
}

/// Errors that can occur when executing a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ExecutionError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur when proving the output of a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ProveError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur when verifying the output of a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VerifyError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("invalid proof")]
    InvalidProof,
}

/// Errors that can occur when decoding values.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum DecodeError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// This trait provides an abstraction of MPC, modeling it as a multi-threaded virtual machine.
#[async_trait]
pub trait Vm {
    /// The type of thread.
    type Thread: Thread + Send + 'static;

    /// Creates a new thread.
    async fn new_thread(&mut self, id: &str) -> Result<Self::Thread, VmError>;

    /// Creates a new thread pool.
    async fn new_thread_pool(
        &mut self,
        id: &str,
        thread_count: usize,
    ) -> Result<ThreadPool<Self::Thread>, VmError> {
        let mut id = NestedId::new(id).append_counter();
        let mut threads = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            threads.push(
                self.new_thread(&id.increment_in_place().to_string())
                    .await?,
            );
        }
        Ok(ThreadPool::new(threads))
    }
}

/// This trait provides an abstraction of a thread in an MPC virtual machine.
pub trait Thread: Memory {}

/// This trait provides methods for interacting with values in memory.
pub trait Memory {
    /// Adds a new public input value, returning a reference to it.
    fn new_public_input<T: StaticValueType>(
        &self,
        id: &str,
        value: T,
    ) -> Result<ValueRef, MemoryError>;

    /// Adds a new public array input value, returning a reference to it.
    fn new_public_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Vec<T>,
    ) -> Result<ValueRef, MemoryError>
    where
        Vec<T>: Into<Value>;

    /// Adds a new private input value, returning a reference to it.
    fn new_private_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<T>,
    ) -> Result<ValueRef, MemoryError>;

    /// Adds a new private array input value, returning a reference to it.
    fn new_private_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<Vec<T>>,
        len: usize,
    ) -> Result<ValueRef, MemoryError>
    where
        Vec<T>: Into<Value>;

    /// Creates a new output value, returning a reference to it.
    fn new_output<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, MemoryError>;

    /// Creates a new array output value, returning a reference to it.
    fn new_array_output<T: StaticValueType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, MemoryError>
    where
        Vec<T>: Into<Value>;

    /// Returns a value if it exists.
    fn get_value(&self, id: &str) -> Option<ValueRef>;
}

/// This trait provides methods for executing a circuit.
#[async_trait]
pub trait Execute {
    /// Executes a circuit with the provided inputs, assigning to the provided output values
    async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ExecutionError>;
}

/// This trait provides methods for proving the output of a circuit.
#[async_trait]
pub trait Prove {
    /// Proves the output of the circuit with the provided inputs, assigning to the provided output values
    async fn prove(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ProveError>;
}

/// This trait provides methods for verifying the output of a circuit.
#[async_trait]
pub trait Verify {
    /// Verifies the output of the circuit with the provided inputs, assigning to the provided output values
    async fn verify(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        expected_outputs: &[Value],
    ) -> Result<(), VerifyError>;
}

/// This trait provides methods for decoding values.
#[async_trait]
pub trait Decode {
    /// Decodes the provided values, returning the plaintext values to all parties.
    async fn decode(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError>;
}

#[cfg(test)]
mod tests {
    use mpc_circuits::{circuits::AES128, types::StaticValueType};
    use mpc_garble_core::msg::GarbleMessage;
    use mpc_ot::mock::mock_ot_pair;
    use utils_aio::duplex::DuplexChannel;

    use crate::{
        config::ValueConfig,
        evaluator::Evaluator,
        generator::{Generator, GeneratorConfigBuilder},
        registry::ValueRegistry,
    };

    #[tokio::test]
    async fn test_semi_honest() {
        let (mut gen_channel, mut ev_channel) = DuplexChannel::<GarbleMessage>::new();
        let (ot_send, ot_recv) = mock_ot_pair();

        let gen = Generator::new(
            GeneratorConfigBuilder::default().build().unwrap(),
            [0u8; 32],
        );
        let ev = Evaluator::default();

        let mut value_registry = ValueRegistry::default();

        let key = [69u8; 16];
        let msg = [42u8; 16];

        let key_ref = value_registry
            .add_value("key", <[u8; 16]>::value_type())
            .unwrap();
        let msg_ref = value_registry
            .add_value("msg", <[u8; 16]>::value_type())
            .unwrap();
        let ciphertext_ref = value_registry
            .add_value("ciphertext", <[u8; 16]>::value_type())
            .unwrap();

        let gen_fut = async {
            gen.setup_inputs(
                "test",
                &[
                    ValueConfig::new_private::<[u8; 16]>(key_ref.clone(), Some(key)).unwrap(),
                    ValueConfig::new_private::<[u8; 16]>(msg_ref.clone(), None).unwrap(),
                ],
                &mut gen_channel,
                &ot_send,
            )
            .await
            .unwrap();

            gen.generate(
                AES128.clone(),
                &[key_ref.clone(), msg_ref.clone()],
                &[ciphertext_ref.clone()],
                &mut gen_channel,
                false,
            )
            .await
            .unwrap();
        };

        let ev_fut = async {
            ev.setup_inputs(
                "test",
                &[
                    ValueConfig::new_private::<[u8; 16]>(key_ref.clone(), None).unwrap(),
                    ValueConfig::new_private::<[u8; 16]>(msg_ref.clone(), Some(msg)).unwrap(),
                ],
                &mut ev_channel,
                &ot_recv,
            )
            .await
            .unwrap();

            _ = ev
                .evaluate(
                    AES128.clone(),
                    &[key_ref.clone(), msg_ref.clone()],
                    &[ciphertext_ref.clone()],
                    &mut ev_channel,
                )
                .await
                .unwrap();
        };

        tokio::join!(gen_fut, ev_fut);

        let ciphertext_full_encoding = gen.get_encoding(&ciphertext_ref).unwrap();
        let ciphertext_active_encoding = ev.get_encoding(&ciphertext_ref).unwrap();

        let decoding = ciphertext_full_encoding.decoding();
        let ciphertext: [u8; 16] = ciphertext_active_encoding
            .decode(&decoding)
            .unwrap()
            .try_into()
            .unwrap();

        let expected: [u8; 16] = {
            use aes::{Aes128, BlockEncrypt, NewBlockCipher};

            let mut msg = msg.into();

            let cipher = Aes128::new_from_slice(&key).unwrap();
            cipher.encrypt_block(&mut msg);

            msg.into()
        };

        assert_eq!(ciphertext, expected)
    }
}
