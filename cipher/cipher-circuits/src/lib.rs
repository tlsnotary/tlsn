mod aes_ctr;
mod aes_ctr_masked;
mod aes_masked;

pub use aes_ctr::aes_ctr;
pub use aes_ctr_masked::aes_ctr_masked;
pub use aes_masked::aes_masked;

use once_cell::sync::Lazy;
use std::sync::Arc;

use mpc_circuits::Circuit;

/// Encrypt plaintext or decrypt ciphertext in AES-CTR mode
///
/// TEXT could also just be used as a mask for the encrypted counter-block.
///
/// # Inputs
///
///   0. KEY: 16-byte encryption key
///   1. IV: 4-byte initialization-vector
///   2. TEXT: 16-byte text (plaintext or ciphertext)
///   3. NONCE: 8-byte Explicit Nonce
///   4. CTR: U32 Counter
///
/// # Outputs
///
///   0. T_OUT: 16-byte output (plaintext or ciphertext)
pub static AES_CTR: Lazy<Arc<Circuit>> = Lazy::new(aes_ctr);

/// AES encrypt counter-block and apply two XOR masks
///
/// # Inputs
///
///   0. KEY: 16-byte encryption key
///   1. IV: 4-byte initialization-vector
///   2. NONCE: 8-byte Explicit Nonce
///   3. CTR: U32 Counter
///   4. MASK_0: 16-byte XOR mask
///   5. MASK_1: 16-byte XOR mask
///
/// # Outputs
///
///   0. C_MASKED: 16-byte masked key block (C + MASK_0 + MASK_1)
pub static AES_CTR_MASKED: Lazy<Arc<Circuit>> = Lazy::new(aes_ctr_masked);

/// Encrypt plaintext and apply XOR masks
///
/// # Inputs
///
///   0. KEY: 16-byte encryption key
///   1. TEXT: 16-byte plaintext
///   2. MASK_0: 16-byte XOR mask
///   3. MASK_1: 16-byte XOR mask
///
/// # Outputs
///
///   0. C_MASKED: 16-byte output (CIPHERTEXT + MASK_0 + MASK_1)
pub static AES_MASKED: Lazy<Arc<Circuit>> = Lazy::new(aes_masked);
