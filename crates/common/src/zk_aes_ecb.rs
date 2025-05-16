//! Zero-knowledge AES-ECB encryption of counter blocks.

use cipher::{aes::Aes128, Cipher, CtrBlock};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array,
};
use mpz_vm_core::{prelude::*, Vm};

type Nonce = Array<U8, 8>;
type Ctr = Array<U8, 4>;
type Block = Array<U8, 16>;

/// ZK AES-ECB encryption.
#[derive(Debug)]
pub struct ZkAesEcb {
    aes: Aes128,
    state: State,
}

impl ZkAesEcb {
    /// Creates a new ZK AES-ECB instance.
    pub fn new() -> Self {
        Self {
            aes: Aes128::default(),
            state: State::Init,
        }
    }

    /// Allocates `count` counter blocks for encryption.
    pub fn alloc(&mut self, vm: &mut dyn Vm<Binary>, count: usize) -> Result<(), ZkAesEcbError> {
        let State::Init = self.state.take() else {
            Err(ErrorRepr::State {
                reason: "must be in init state to allocate",
            })?
        };

        let blocks = (0..count)
            .map(|_| self.aes.alloc_ctr_block(vm).map_err(ZkAesEcbError::vm))
            .collect::<Result<Vec<_>, ZkAesEcbError>>()?;

        self.state = State::Ready { blocks };

        Ok(())
    }

    /// Sets the key and IV for the cipher.
    pub fn set_key(&mut self, key: Array<U8, 16>, iv: Array<U8, 4>) {
        self.aes.set_key(key);
        self.aes.set_iv(iv);
    }

    /// Proves the encryption of counter blocks.
    ///
    /// Here we only assign certain values in the VM but the actual proving
    /// happens later when the plaintext is assigned and the VM is executed.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `nonce_ctr` - Explicit nonce and counter to assign to each block.
    ///
    /// # Returns
    ///
    /// A VM reference to the ciphertext.
    pub fn encrypt(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        nonce_ctr: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Vec<Array<U8, 16>>, ZkAesEcbError> {
        let State::Ready { blocks } = &mut self.state else {
            Err(ErrorRepr::State {
                reason: "must be in ready state to encrypt",
            })?
        };

        if nonce_ctr.len() > blocks.len() {
            Err(ErrorRepr::InsufficientAllocation {
                expected: nonce_ctr.len(),
                actual: blocks.len(),
            })?
        }

        let output_refs = nonce_ctr
            .into_iter()
            .zip(blocks)
            .map(|((explicit_nonce, ctr), block)| {
                let explicit_nonce: [u8; 8] =
                    explicit_nonce
                        .try_into()
                        .map_err(|explicit_nonce: Vec<_>| ErrorRepr::ExplicitNonceLength {
                            expected: 8,
                            actual: explicit_nonce.len(),
                        })?;

                let counter: [u8; 4] =
                    ctr.try_into()
                        .map_err(|ctr: Vec<_>| ErrorRepr::CounterLength {
                            expected: 4,
                            actual: ctr.len(),
                        })?;

                vm.assign(block.explicit_nonce, explicit_nonce)
                    .map_err(ZkAesEcbError::vm)?;
                vm.commit(block.explicit_nonce).map_err(ZkAesEcbError::vm)?;
                vm.assign(block.counter, counter)
                    .map_err(ZkAesEcbError::vm)?;
                vm.commit(block.counter).map_err(ZkAesEcbError::vm)?;

                Ok(block.output)
            })
            .collect::<Result<Vec<_>, ZkAesEcbError>>()?;

        Ok(output_refs)
    }
}

enum State {
    Init,
    Ready {
        blocks: Vec<CtrBlock<Nonce, Ctr, Block>>,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Init => write!(f, "Init"),
            State::Ready { .. } => write!(f, "Ready"),
            State::Error => write!(f, "Error"),
        }
    }
}

/// Error for [`ZkAesEcb`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ZkAesEcbError(#[from] ErrorRepr);

impl ZkAesEcbError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("zk aes error")]
enum ErrorRepr {
    #[error("invalid state: {reason}")]
    State { reason: &'static str },
    #[error("vm error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("invalid explicit nonce length: expected {expected}, got {actual}")]
    ExplicitNonceLength { expected: usize, actual: usize },
    #[error("invalid counter length: expected {expected}, got {actual}")]
    CounterLength { expected: usize, actual: usize },
    #[error("insufficient allocation: expected {expected}, got {actual}")]
    InsufficientAllocation { expected: usize, actual: usize },
}
