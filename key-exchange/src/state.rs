use std::sync::Arc;

use mpc_circuits::Circuit;
use p256::{PublicKey, SecretKey};
use share_conversion_core::fields::p256::P256;

mod sealed {
    pub trait Sealed {}

    impl<P, A, D> Sealed for super::KeyExchangeSetup<P, A, D> {}
    impl<P, D> Sealed for super::PMSComputationSetup<P, D> {}
}

pub trait State: sealed::Sealed {}

pub struct KeyExchangeSetup<P, A, D> {
    pub(crate) point_addition_sender: P,
    pub(crate) point_addition_receiver: P,
    pub(crate) dual_ex_factory: A,
    pub(crate) private_key: Option<SecretKey>,
    pub(crate) server_key: Option<PublicKey>,
    pub(crate) _phantom_data: std::marker::PhantomData<D>,
}

pub struct PMSComputationSetup<P, D> {
    pub(crate) point_addition_sender: P,
    pub(crate) point_addition_receiver: P,
    pub(crate) private_key: SecretKey,
    pub(crate) server_key: PublicKey,
    pub(crate) pms_shares: Option<[P256; 2]>,
    pub(crate) dual_ex: D,
    pub(crate) circuit: Arc<Circuit>,
}

impl<P, A, D> State for KeyExchangeSetup<P, A, D> {}
impl<P, D> State for PMSComputationSetup<P, D> {}
