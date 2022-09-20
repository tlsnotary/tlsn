use std::convert::TryInto;

use super::{P256SecretShare, PointAdditionError, P};
use crate::msgs::point_addition as msgs;
use curv::arithmetic::{Converter, Modulo, Samplable};
use p256::EncodedPoint;
use paillier::*;

pub mod state {
    use super::*;
    mod sealed {
        use super::*;
        pub trait Sealed {}
        impl Sealed for Initialized {}
        impl Sealed for S1 {}
        impl Sealed for S2 {}
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
        /// Follower's additive share
        pub(super) secret: BigInt,
        /// Masks
        pub(super) masks: Masks,
    }
    pub struct S1 {
        /// NIST P-256 modulus
        pub(super) p: BigInt,
        /// Leader's Paillier encryption key
        pub(super) enc_key: EncryptionKey,
        /// Follower's additive share
        pub(super) secret: BigInt,
        /// Masks
        pub(super) masks: Masks,
        /// E(-x_p)
        pub(super) e_neg_x_p: BigInt,
        /// E(-x_q)
        pub(super) e_neg_x_q: BigInt,
    }
    pub struct S2 {
        /// NIST P-256 modulus
        pub(super) p: BigInt,
        /// Leader's Paillier encryption key
        pub(super) enc_key: EncryptionKey,
        /// Follower's additive share
        pub(super) secret: BigInt,
        /// Masks
        pub(super) masks: Masks,
        /// E(-x_p)
        pub(super) e_neg_x_p: BigInt,
        /// E(-x_q)
        pub(super) e_neg_x_q: BigInt,
    }
    pub struct Complete {
        /// NIST P-256 modulus
        pub(super) p: BigInt,
        /// Follower's additive share
        pub(super) secret: BigInt,
    }

    impl State for Initialized {}
    impl State for S1 {}
    impl State for S2 {}
    impl State for Complete {}
}

use state::*;

pub struct PointAdditionFollower<S: State = Initialized> {
    state: S,
}

struct Masks {
    /// Mask N_A
    n_a: BigInt,
    /// Mask N_T
    n_t: BigInt,
    /// Mask N_B
    n_b: BigInt,
    /// Mask M_A
    m_a: BigInt,
    /// Mask M_T
    m_t: BigInt,
    /// Mask M_B
    m_b: BigInt,
}

impl Masks {
    pub fn generate() -> Self {
        Self {
            n_a: BigInt::sample(1024),
            n_t: BigInt::sample(512),
            n_b: BigInt::sample(1024),
            m_a: BigInt::sample(512),
            m_t: BigInt::sample(256),
            m_b: BigInt::sample(512),
        }
    }
}

impl PointAdditionFollower {
    pub fn new(point: &EncodedPoint) -> Self {
        Self {
            state: Initialized {
                x: BigInt::from_bytes(point.x().expect("Invalid point")),
                y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
                p: BigInt::from_hex(P).unwrap(),
                masks: Masks::generate(),
                secret: BigInt::sample(1027),
            },
        }
    }

    pub fn next(self, msg: msgs::M1) -> (msgs::S1, PointAdditionFollower<S1>) {
        // Computes E(T) = E(x_q - x_p)
        let e_x_q: RawCiphertext = msg.e_x_q.into();
        let e_neg_x_p = Paillier::encrypt(
            &msg.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.state.p, &self.state.x, &self.state.p)),
        );
        let e_t = Paillier::add(&msg.enc_key, e_x_q, e_neg_x_p.clone());

        // Computes E(T * M_T + N_T)
        let e_n_t = Paillier::encrypt(&msg.enc_key, RawPlaintext::from(&self.state.masks.n_t));
        let e_t_m_t = Paillier::mul(&msg.enc_key, e_t, RawPlaintext::from(&self.state.masks.m_t));
        let e_t_masked = Paillier::add(&msg.enc_key, e_t_m_t, e_n_t);

        // Computes E(A) = E(y_p^2) + E(y_q^2) + E(-2y_q) * y_p
        let e_y_q_pow_2: RawCiphertext = msg.e_y_q_pow_2.into();
        let e_neg_2_y_q: RawCiphertext = msg.e_neg_2_y_q.into();
        let e_y_p_pow_2 = Paillier::encrypt(
            &msg.enc_key,
            RawPlaintext::from(BigInt::mod_pow(
                &self.state.y,
                &BigInt::from(2_u16),
                &self.state.p,
            )),
        );
        let e_y_pq_pow_2 = Paillier::add(&msg.enc_key, e_y_p_pow_2, e_y_q_pow_2);
        let e_neg_2_y_q_y_p =
            Paillier::mul(&msg.enc_key, e_neg_2_y_q, RawPlaintext::from(&self.state.y));
        let e_a = Paillier::add(&msg.enc_key, e_y_pq_pow_2, e_neg_2_y_q_y_p);

        // Computes E(A * M_A + N_A)
        let e_a_m_a = Paillier::mul(&msg.enc_key, e_a, RawPlaintext::from(&self.state.masks.m_a));
        let e_n_a = Paillier::encrypt(&msg.enc_key, RawPlaintext::from(&self.state.masks.n_a));
        let e_a_masked = Paillier::add(&msg.enc_key, e_a_m_a, e_n_a);

        let e_a_masked: BigInt = Paillier::rerandomize(&msg.enc_key, e_a_masked).into();
        let e_t_masked: BigInt = Paillier::rerandomize(&msg.enc_key, e_t_masked).into();

        (
            msgs::S1 {
                n_a_mod_p: &self.state.masks.n_a % &self.state.p,
                n_t_mod_p: &self.state.masks.n_t % &self.state.p,
                e_a_masked,
                e_t_masked,
            },
            PointAdditionFollower {
                state: S1 {
                    p: self.state.p,
                    enc_key: msg.enc_key,
                    secret: self.state.secret,
                    masks: self.state.masks,
                    e_neg_x_p: msg.e_neg_x_q,
                    e_neg_x_q: BigInt::from(e_neg_x_p),
                },
            },
        )
    }
}

impl PointAdditionFollower<S1> {
    pub fn next(self, msg: msgs::M2) -> (msgs::S2, PointAdditionFollower<S2>) {
        // Computes E(B) = E((T * M_T)^p-3 mod p) * (M_T^p-3)^-1 mod p
        let inv = BigInt::mod_inv(
            &BigInt::mod_pow(&self.state.masks.m_t, &(&self.state.p - 3), &self.state.p),
            &self.state.p,
        )
        .unwrap();

        let e_b = Paillier::mul(
            &self.state.enc_key,
            RawCiphertext::from(msg.e_t_mod_pow),
            RawPlaintext::from(inv),
        );

        // Computes E(B * M_C + N_C)
        let e_b_m_b = Paillier::mul(
            &self.state.enc_key,
            e_b,
            RawPlaintext::from(&self.state.masks.m_b),
        );
        let e_n_b = Paillier::encrypt(
            &self.state.enc_key,
            RawPlaintext::from(&self.state.masks.n_b),
        );
        let e_b_masked = Paillier::add(&self.state.enc_key, e_b_m_b, e_n_b);

        (
            msgs::S2 {
                n_b_mod_p: &self.state.masks.n_b % &self.state.p,
                e_b_masked: Paillier::rerandomize(&self.state.enc_key, e_b_masked).into(),
            },
            PointAdditionFollower {
                state: S2 {
                    p: self.state.p,
                    enc_key: self.state.enc_key,
                    secret: self.state.secret,
                    masks: self.state.masks,
                    e_neg_x_p: self.state.e_neg_x_p,
                    e_neg_x_q: self.state.e_neg_x_q,
                },
            },
        )
    }
}

impl PointAdditionFollower<S2> {
    pub fn next(self, msg: msgs::M3) -> (msgs::S3, PointAdditionFollower<Complete>) {
        // Computes E(A * B)
        let inv = BigInt::mod_inv(
            &BigInt::mod_mul(&self.state.masks.m_a, &self.state.masks.m_b, &self.state.p),
            &self.state.p,
        )
        .unwrap();

        let e_a_b = Paillier::mul(
            &self.state.enc_key,
            RawCiphertext::from(msg.e_ab_masked),
            RawPlaintext::from(inv),
        );

        // Computes E(PMS + S_q)
        let e_pms = Paillier::add(
            &self.state.enc_key,
            Paillier::add(
                &self.state.enc_key,
                e_a_b,
                RawCiphertext::from(&self.state.e_neg_x_q),
            ),
            RawCiphertext::from(&self.state.e_neg_x_p),
        );
        let e_secret =
            Paillier::encrypt(&self.state.enc_key, RawPlaintext::from(&self.state.secret));
        let e_pms_masked = Paillier::add(&self.state.enc_key, e_pms, e_secret);

        (
            msgs::S3 {
                e_pms_masked: Paillier::rerandomize(&self.state.enc_key, e_pms_masked).into(),
            },
            PointAdditionFollower {
                state: Complete {
                    p: self.state.p,
                    secret: self.state.secret,
                },
            },
        )
    }
}

impl PointAdditionFollower<Complete> {
    pub fn finalize(self) -> Result<P256SecretShare, PointAdditionError> {
        let keyshare = &self.state.p - (self.state.secret % &self.state.p);

        keyshare
            .try_into()
            .map_err(|_| PointAdditionError::InvalidKeyshare)
    }
}
