//! 2-Party Elliptic curve secret-sharing using Paillier Cryptosystem

use super::master::{MasterStepOne, MasterStepThree, MasterStepTwo};
use super::{SecretShare, P};
use curv::arithmetic::{Converter, Modulo, Samplable};
use p256::EncodedPoint;
use paillier::*;

pub struct Initialized {
    /// X coordinate of slave's secret
    x: BigInt,
    /// Y coordinate of slave's secret
    y: BigInt,
}
pub struct StepOne {
    /// Master's Paillier encryption key
    enc_key: EncryptionKey,
    /// E(-x_p)
    e_neg_x_p: BigInt,
    /// E(-x_q)
    e_neg_x_q: BigInt,
}
pub struct StepTwo {
    /// Master's Paillier encryption key
    enc_key: EncryptionKey,
    /// E(-x_p)
    e_neg_x_p: BigInt,
    /// E(-x_q)
    e_neg_x_q: BigInt,
}
pub struct Complete;

pub trait State {}
impl State for Initialized {}
impl State for StepOne {}
impl State for StepTwo {}
impl State for Complete {}

pub struct SecretShareSlave<S>
where
    S: State,
{
    /// Current state of secret share protocol
    state: S,
    /// NIST P-256 Prime
    p: BigInt,
    /// Slave's share of PMS
    secret: BigInt,
    /// Masks
    masks: Masks,
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

pub struct SlaveStepOne {
    /// N_A mod p
    pub(super) n_a_mod_p: BigInt,
    /// N_T mod p
    pub(super) n_t_mod_p: BigInt,
    /// E(A * M_A + N_A)
    pub(super) e_a_masked: BigInt,
    /// E(T * M_T + N_T)
    pub(super) e_t_masked: BigInt,
}

pub struct SlaveStepTwo {
    /// N_B mod p
    pub(super) n_b_mod_p: BigInt,
    /// E(B * M_C + N_C)
    pub(super) e_b_masked: BigInt,
}

pub struct SlaveStepThree {
    /// E(PMS + S_q)
    pub(super) e_pms_masked: BigInt,
}

impl SecretShareSlave<Initialized> {
    pub fn new(point: &EncodedPoint) -> Self {
        Self {
            state: Initialized {
                x: BigInt::from_bytes(point.x().expect("Invalid point")),
                y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
            },
            p: BigInt::from_hex(P).unwrap(),
            masks: Masks::generate(),
            secret: BigInt::sample(1027),
        }
    }

    pub fn from_secret(point: EncodedPoint, secret: BigInt) -> Self {
        Self {
            state: Initialized {
                x: BigInt::from_bytes(point.x().expect("Invalid point")),
                y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
            },
            p: BigInt::from_hex(P).unwrap(),
            masks: Masks::generate(),
            secret,
        }
    }

    pub fn next(self, m: MasterStepOne) -> (SlaveStepOne, SecretShareSlave<StepOne>) {
        // Computes E(T) = E(x_q - x_p)
        let e_x_q: RawCiphertext = m.e_x_q.into();
        let e_neg_x_p = Paillier::encrypt(
            &m.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.p, &self.state.x, &self.p)),
        );
        let e_t = Paillier::add(&m.enc_key, e_x_q, e_neg_x_p.clone());

        // Computes E(T * M_T + N_T)
        let e_n_t = Paillier::encrypt(&m.enc_key, RawPlaintext::from(&self.masks.n_t));
        let e_t_m_t = Paillier::mul(&m.enc_key, e_t, RawPlaintext::from(&self.masks.m_t));
        let e_t_masked = Paillier::add(&m.enc_key, e_t_m_t, e_n_t);

        // Computes E(A) = E(y_p^2) + E(y_q^2) + E(-2y_q) * y_p
        let e_y_q_pow_2: RawCiphertext = m.e_y_q_pow_2.into();
        let e_neg_2_y_q: RawCiphertext = m.e_neg_2_y_q.into();
        let e_y_p_pow_2 = Paillier::encrypt(
            &m.enc_key,
            RawPlaintext::from(BigInt::mod_pow(
                &self.state.y,
                &BigInt::from(2_u16),
                &self.p,
            )),
        );
        let e_y_pq_pow_2 = Paillier::add(&m.enc_key, e_y_p_pow_2, e_y_q_pow_2);
        let e_neg_2_y_q_y_p =
            Paillier::mul(&m.enc_key, e_neg_2_y_q, RawPlaintext::from(&self.state.y));
        let e_a = Paillier::add(&m.enc_key, e_y_pq_pow_2, e_neg_2_y_q_y_p);

        // Computes E(A * M_A + N_A)
        let e_a_m_a = Paillier::mul(&m.enc_key, e_a, RawPlaintext::from(&self.masks.m_a));
        let e_n_a = Paillier::encrypt(&m.enc_key, RawPlaintext::from(&self.masks.n_a));
        let e_a_masked = Paillier::add(&m.enc_key, e_a_m_a, e_n_a);

        let e_a_masked: BigInt = Paillier::rerandomize(&m.enc_key, e_a_masked).into();
        let e_t_masked: BigInt = Paillier::rerandomize(&m.enc_key, e_t_masked).into();

        (
            SlaveStepOne {
                n_a_mod_p: &self.masks.n_a % &self.p,
                n_t_mod_p: &self.masks.n_t % &self.p,
                e_a_masked,
                e_t_masked,
            },
            SecretShareSlave {
                state: StepOne {
                    enc_key: m.enc_key,
                    e_neg_x_q: m.e_neg_x_q,
                    e_neg_x_p: BigInt::from(e_neg_x_p),
                },
                p: self.p,
                masks: self.masks,
                secret: self.secret,
            },
        )
    }
}

impl SecretShareSlave<StepOne> {
    pub fn next(self, m: MasterStepTwo) -> (SlaveStepTwo, SecretShareSlave<StepTwo>) {
        // Computes E(B) = E((T * M_T)^p-3 mod p) * (M_T^p-3)^-1 mod p
        let inv = BigInt::mod_inv(
            &BigInt::mod_pow(&self.masks.m_t, &(&self.p - 3), &self.p),
            &self.p,
        )
        .unwrap();
        let e_b = Paillier::mul(
            &self.state.enc_key,
            RawCiphertext::from(m.e_t_mod_pow),
            RawPlaintext::from(inv),
        );

        // Computes E(B * M_C + N_C)
        let e_b_m_b = Paillier::mul(
            &self.state.enc_key,
            e_b,
            RawPlaintext::from(&self.masks.m_b),
        );
        let e_n_b = Paillier::encrypt(&self.state.enc_key, RawPlaintext::from(&self.masks.n_b));
        let e_b_masked = Paillier::add(&self.state.enc_key, e_b_m_b, e_n_b);

        (
            SlaveStepTwo {
                n_b_mod_p: &self.masks.n_b % &self.p,
                e_b_masked: Paillier::rerandomize(&self.state.enc_key, e_b_masked).into(),
            },
            SecretShareSlave {
                state: StepTwo {
                    enc_key: self.state.enc_key,
                    e_neg_x_q: self.state.e_neg_x_q,
                    e_neg_x_p: self.state.e_neg_x_p,
                },
                p: self.p,
                masks: self.masks,
                secret: self.secret,
            },
        )
    }
}

impl SecretShareSlave<StepTwo> {
    pub fn next(self, m: MasterStepThree) -> (SlaveStepThree, SecretShareSlave<Complete>) {
        // Computes E(A * B)
        let inv = BigInt::mod_inv(
            &BigInt::mod_mul(&self.masks.m_a, &self.masks.m_b, &self.p),
            &self.p,
        )
        .unwrap();
        let e_a_b = Paillier::mul(
            &self.state.enc_key,
            RawCiphertext::from(m.e_ab_masked),
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
        let e_secret = Paillier::encrypt(&self.state.enc_key, RawPlaintext::from(&self.secret));
        let e_pms_masked = Paillier::add(&self.state.enc_key, e_pms, e_secret);

        (
            SlaveStepThree {
                e_pms_masked: Paillier::rerandomize(&self.state.enc_key, e_pms_masked).into(),
            },
            SecretShareSlave {
                state: Complete,
                p: self.p,
                masks: self.masks,
                secret: self.secret,
            },
        )
    }
}

impl SecretShareSlave<Complete> {
    pub fn secret(self) -> SecretShare {
        &self.p - (self.secret % &self.p)
    }
}
