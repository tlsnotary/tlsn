use std::convert::TryInto;

use super::{P256SecretShare, PointAdditionError, P};
use crate::msgs::point_addition as msgs;
use curv::arithmetic::{Converter, Modulo};
use p256::EncodedPoint;
use paillier::*;

pub mod state {
    use super::*;
    mod sealed {
        use super::*;
        pub trait Sealed {}
        impl Sealed for Initialized {}
        impl Sealed for M1 {}
        impl Sealed for M2 {}
        impl Sealed for Complete {}
    }

    pub trait State: sealed::Sealed {}
    pub struct Initialized {
        /// NIST P-256 modulus
        pub(super) p: BigInt,
        /// X coordinate of leader's secret
        pub(super) x: BigInt,
        /// Y coordinate of leader's secret
        pub(super) y: BigInt,
        /// Leader's Paillier encryption key
        pub(super) enc_key: EncryptionKey,
        /// Leader's Paillier decryption key
        pub(super) dec_key: DecryptionKey,
    }
    pub struct M1 {
        /// NIST P-256 modulus
        pub(super) p: BigInt,
        /// Leader's Paillier encryption key
        pub(super) enc_key: EncryptionKey,
        /// Leader's Paillier decryption key
        pub(super) dec_key: DecryptionKey,
    }
    pub struct M2 {
        /// NIST P-256 modulus
        pub(super) p: BigInt,
        /// Leader's Paillier encryption key
        pub(super) enc_key: EncryptionKey,
        /// Leader's Paillier decryption key
        pub(super) dec_key: DecryptionKey,
        /// temp value stored between communication rounds
        pub(super) a_masked_mod_p: BigInt,
    }
    pub struct Complete {
        /// NIST P-256 modulus
        pub(super) p: BigInt,
        /// Leader's Paillier decryption key
        pub(super) dec_key: DecryptionKey,
    }

    impl State for Initialized {}
    impl State for M1 {}
    impl State for M2 {}
    impl State for Complete {}
}

use state::*;

pub struct PointAdditionLeader<S: State = Initialized> {
    state: S,
}

impl PointAdditionLeader {
    pub fn new(point: &EncodedPoint) -> Self {
        let (enc_key, dec_key) = Paillier::keypair().keys();
        Self {
            state: Initialized {
                x: BigInt::from_bytes(point.x().expect("Invalid point")),
                y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
                p: BigInt::from_hex(P).unwrap(),
                enc_key,
                dec_key,
            },
        }
    }

    pub fn next(self) -> (msgs::M1, PointAdditionLeader<M1>) {
        // Computes E(x_q)
        let e_x_q: BigInt =
            Paillier::encrypt(&self.state.enc_key, RawPlaintext::from(&self.state.x)).into();

        // Computes E(-x_q)
        let e_neg_x_q: BigInt = Paillier::encrypt(
            &self.state.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.state.p, &self.state.x, &self.state.p)),
        )
        .into();

        // Computes E(y_q^2)
        let e_y_q_pow_2: BigInt = Paillier::encrypt(
            &self.state.enc_key,
            RawPlaintext::from(BigInt::mod_pow(
                &self.state.y,
                &BigInt::from(2_u16),
                &self.state.p,
            )),
        )
        .into();

        // Computes E(-2y_q)
        let e_neg_2_y_q: BigInt = Paillier::encrypt(
            &self.state.enc_key,
            RawPlaintext::from(BigInt::mod_sub(
                &self.state.p,
                &(2 * &self.state.y),
                &self.state.p,
            )),
        )
        .into();

        (
            msgs::M1 {
                enc_key: self.state.enc_key.clone(),
                e_x_q,
                e_neg_x_q,
                e_y_q_pow_2,
                e_neg_2_y_q,
            },
            PointAdditionLeader {
                state: M1 {
                    p: self.state.p,
                    enc_key: self.state.enc_key,
                    dec_key: self.state.dec_key,
                },
            },
        )
    }
}

impl PointAdditionLeader<M1> {
    pub fn next(self, msg: msgs::S1) -> (msgs::M2, PointAdditionLeader<M2>) {
        // Computes A * M_A mod p
        let a_masked: BigInt =
            Paillier::decrypt(&self.state.dec_key, RawCiphertext::from(msg.e_a_masked)).into();
        let a_masked_mod_p = BigInt::mod_sub(&a_masked, &msg.n_a_mod_p, &self.state.p);

        // Computes T * M_T mod p
        let t_masked: BigInt =
            Paillier::decrypt(&self.state.dec_key, RawCiphertext::from(msg.e_t_masked)).into();
        let t_masked_mod_p = BigInt::mod_sub(&t_masked, &msg.n_t_mod_p, &self.state.p);

        // Computes E((T * M_T)^p-3 mod p)
        let t_mod_pow = BigInt::mod_pow(&t_masked_mod_p, &(&self.state.p - 3), &self.state.p);
        let e_t_mod_pow: BigInt =
            Paillier::encrypt(&self.state.enc_key, RawPlaintext::from(t_mod_pow)).into();

        (
            msgs::M2 { e_t_mod_pow },
            PointAdditionLeader {
                state: M2 {
                    p: self.state.p,
                    enc_key: self.state.enc_key,
                    dec_key: self.state.dec_key,
                    a_masked_mod_p,
                },
            },
        )
    }
}

impl PointAdditionLeader<M2> {
    pub fn next(self, s: msgs::S2) -> (msgs::M3, PointAdditionLeader<Complete>) {
        // Computes B * M_B mod p
        let b_masked: BigInt =
            Paillier::decrypt(&self.state.dec_key, RawCiphertext::from(s.e_b_masked)).into();
        let b_masked_mod_p = BigInt::mod_sub(&b_masked, &s.n_b_mod_p, &self.state.p);

        // Computes E(A * M_A * B * M_B)
        let e_ab_masked: BigInt = Paillier::encrypt(
            &self.state.enc_key,
            RawPlaintext::from(BigInt::mod_mul(
                &b_masked_mod_p,
                &self.state.a_masked_mod_p,
                &self.state.p,
            )),
        )
        .into();

        (
            msgs::M3 { e_ab_masked },
            PointAdditionLeader {
                state: Complete {
                    p: self.state.p,
                    dec_key: self.state.dec_key,
                },
            },
        )
    }
}

impl PointAdditionLeader<Complete> {
    pub fn finalize(self, msg: msgs::S3) -> Result<P256SecretShare, PointAdditionError> {
        // Computes leader's secret, s_p
        let keyshare: BigInt =
            Paillier::decrypt(&self.state.dec_key, RawCiphertext::from(msg.e_pms_masked)).into();

        (&keyshare % &self.state.p)
            .try_into()
            .map_err(|_| PointAdditionError::InvalidKeyshare)
    }
}
