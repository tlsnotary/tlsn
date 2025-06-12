//! Zero-knowledge AES-CTR encryption.

use cipher::{
    aes::{Aes128, AesError},
    Cipher, CipherError, Keystream,
};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Vector,
};
use mpz_vm_core::{prelude::*, Vm};

use crate::Role;

type Nonce = Array<U8, 8>;
type Ctr = Array<U8, 4>;
type Block = Array<U8, 16>;

const START_CTR: u32 = 2;

/// ZK AES-CTR encryption.
#[derive(Debug)]
pub struct ZkAesCtr {
    role: Role,
    aes: Aes128,
    state: State,
}

impl ZkAesCtr {
    /// Creates a new ZK AES-CTR instance.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            aes: Aes128::default(),
            state: State::Init,
        }
    }

    /// Returns the role.
    pub fn role(&self) -> &Role {
        &self.role
    }

    /// Allocates `len` bytes for encryption.
    pub fn alloc(&mut self, vm: &mut dyn Vm<Binary>, len: usize) -> Result<(), ZkAesCtrError> {
        let State::Init = self.state.take() else {
            Err(ErrorRepr::State {
                reason: "must be in init state to allocate",
            })?
        };

        // Round up to the nearest block size.
        let len = 16 * len.div_ceil(16);

        let input = vm.alloc_vec::<U8>(len).map_err(ZkAesCtrError::vm)?;
        let keystream = self.aes.alloc_keystream(vm, len)?;

        match self.role {
            Role::Prover => vm.mark_private(input).map_err(ZkAesCtrError::vm)?,
            Role::Verifier => vm.mark_blind(input).map_err(ZkAesCtrError::vm)?,
        }

        self.state = State::Ready { input, keystream };

        Ok(())
    }

    /// Sets the key and IV for the cipher.
    pub fn set_key(&mut self, key: Array<U8, 16>, iv: Array<U8, 4>) {
        self.aes.set_key(key);
        self.aes.set_iv(iv);
    }

    /// Proves the encryption of `len` bytes.
    ///
    /// Here we only assign certain values in the VM but the actual proving
    /// happens later when the plaintext is assigned and the VM is executed.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `len` - Length of the plaintext in bytes.
    ///
    /// # Returns
    ///
    /// A VM reference to the plaintext and the ciphertext.
    pub fn encrypt(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<(Vector<U8>, Vector<U8>), ZkAesCtrError> {
        let State::Ready { input, keystream } = &mut self.state else {
            Err(ErrorRepr::State {
                reason: "must be in ready state to encrypt",
            })?
        };

        let explicit_nonce: [u8; 8] =
            explicit_nonce
                .try_into()
                .map_err(|explicit_nonce: Vec<_>| ErrorRepr::ExplicitNonceLength {
                    expected: 8,
                    actual: explicit_nonce.len(),
                })?;

        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;
        let padding_len = padded_len - len;

        if padded_len > input.len() {
            Err(ErrorRepr::InsufficientPreprocessing {
                expected: padded_len,
                actual: input.len(),
            })?
        }

        let mut input = input.split_off(input.len() - padded_len);
        let keystream = keystream.consume(padded_len)?;
        let mut output = keystream.apply(vm, input)?;

        // Assign counter block inputs.
        let mut ctr = START_CTR..;
        keystream.assign(vm, explicit_nonce, move || {
            ctr.next().expect("range is unbounded").to_be_bytes()
        })?;

        // Assign zeroes to the padding.
        if padding_len > 0 {
            let padding = input.split_off(input.len() - padding_len);
            // To simplify the impl, we don't mark the padding as public, that's why only
            // the prover assigns it.
            if let Role::Prover = self.role {
                vm.assign(padding, vec![0; padding_len])
                    .map_err(ZkAesCtrError::vm)?;
            }
            vm.commit(padding).map_err(ZkAesCtrError::vm)?;
            output.truncate(len);
        }

        Ok((input, output))
    }
}

enum State {
    Init,
    Ready {
        input: Vector<U8>,
        keystream: Keystream<Nonce, Ctr, Block>,
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

/// Error for [`ZkAesCtr`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ZkAesCtrError(#[from] ErrorRepr);

impl ZkAesCtrError {
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
    #[error("cipher error: {0}")]
    Cipher(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("vm error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("invalid explicit nonce length: expected {expected}, got {actual}")]
    ExplicitNonceLength { expected: usize, actual: usize },
    #[error("insufficient preprocessing: expected {expected}, got {actual}")]
    InsufficientPreprocessing { expected: usize, actual: usize },
}

impl From<AesError> for ZkAesCtrError {
    fn from(err: AesError) -> Self {
        Self(ErrorRepr::Cipher(Box::new(err)))
    }
}

impl From<CipherError> for ZkAesCtrError {
    fn from(err: CipherError) -> Self {
        Self(ErrorRepr::Cipher(Box::new(err)))
    }
}
