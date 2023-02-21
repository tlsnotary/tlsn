use std::sync::Arc;

use mpc_circuits::Circuit;
use p256::{PublicKey, SecretKey};
use share_conversion_core::fields::p256::P256;

use crate::exchange::Role;

mod sealed {
    pub trait Sealed {}

    impl<PS, PR, A, D> Sealed for super::KeyExchangeSetup<PS, PR, A, D> {}
    impl<PS, PR, D> Sealed for super::PMSComputationSetup<PS, PR, D> {}
}

pub trait State: sealed::Sealed {}

pub struct KeyExchangeSetup<PS, PR, A, D> {
    pub(crate) point_addition_sender: PS,
    pub(crate) point_addition_receiver: PR,
    pub(crate) dual_ex_factory: A,
    pub(crate) private_key: Option<SecretKey>,
    pub(crate) server_key: Option<PublicKey>,
    pub(crate) role: Role,
    pub(crate) _phantom_data: std::marker::PhantomData<D>,
}

pub struct PMSComputationSetup<PS, PR, D> {
    pub(crate) point_addition_sender: PS,
    pub(crate) point_addition_receiver: PR,
    pub(crate) private_key: SecretKey,
    pub(crate) server_key: PublicKey,
    pub(crate) pms_shares: Option<[P256; 2]>,
    pub(crate) dual_ex_pms: D,
    pub(crate) dual_ex_xor: D,
    pub(crate) circuit_pms: Arc<Circuit>,
    pub(crate) circuit_xor: Arc<Circuit>,
    pub(crate) role: Role,
}

impl<PS, PR, A, D> State for KeyExchangeSetup<PS, PR, A, D> {}
impl<PS, PR, D> State for PMSComputationSetup<PS, PR, D> {}
