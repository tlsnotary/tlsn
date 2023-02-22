//! This module contains the state for the key exchange instances

use crate::exchange::Role;
use mpc_circuits::Circuit;
use p256::{PublicKey, SecretKey};
use share_conversion_core::fields::p256::P256;
use std::sync::Arc;

mod sealed {
    pub trait Sealed {}

    impl<PS, PR, A, D> Sealed for super::KeyExchangeSetup<PS, PR, A, D> {}
    impl<PS, PR, D> Sealed for super::PMSComputationSetup<PS, PR, D> {}
}

/// A marker trait for the states during key exchange
pub trait State: sealed::Sealed {}

/// The state used during key exchange
pub struct KeyExchangeSetup<PS, PR, A, D> {
    /// The sender instance for performing point addition
    pub(crate) point_addition_sender: PS,
    /// The receiver instance for performing point addition
    pub(crate) point_addition_receiver: PR,
    /// A factory used to instantiate a leader or follower of the garbled circuit dual execution
    /// protocol
    pub(crate) dual_ex_factory: A,
    /// The private key of the user or notary
    pub(crate) private_key: Option<SecretKey>,
    /// The public key of the server
    pub(crate) server_key: Option<PublicKey>,
    /// Determines if this instance is a leader or follower in the key exchange protocol
    pub(crate) role: Role,
    /// `PhantomData` needed for the `dual_ex_factory` field
    pub(crate) _phantom_data: std::marker::PhantomData<D>,
}

/// The state used during the computation of the pre-master secret shares and labels
///
/// Check [KeyExchangeSetup] for a description of the fields
pub struct PMSComputationSetup<PS, PR, D> {
    pub(crate) point_addition_sender: PS,
    pub(crate) point_addition_receiver: PR,
    pub(crate) private_key: SecretKey,
    pub(crate) server_key: PublicKey,
    /// Two different additive shares of the pre-master secret
    pub(crate) pms_shares: Option<[P256; 2]>,
    /// The dual execution instance for the PMS circuit
    pub(crate) dual_ex_pms: D,
    /// The dual execution instance for the XOR circuit
    pub(crate) dual_ex_xor: D,
    /// The circuit for adding the PMS shares
    pub(crate) circuit_pms: Arc<Circuit>,
    /// The circuit for XORing the two different PMSs
    pub(crate) circuit_xor: Arc<Circuit>,
    pub(crate) role: Role,
}

impl<PS, PR, A, D> State for KeyExchangeSetup<PS, PR, A, D> {}
impl<PS, PR, D> State for PMSComputationSetup<PS, PR, D> {}
