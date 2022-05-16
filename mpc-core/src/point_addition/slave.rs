//! 2-Party Elliptic curve secret-sharing using Paillier Cryptosystem

use super::errors::*;
use super::master::{M1, M2, M3};
use super::{SecretShare, SlaveCore, P};
use crate::point_addition::PointAdditionMessage;
use curv::arithmetic::{Converter, Modulo, Samplable};
use p256::EncodedPoint;
use paillier::*;

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    Initialized,
    S1,
    S2,
    Complete,
}

pub struct PointAdditionSlave {
    /// Current state of secret share protocol
    state: State,
    /// NIST P-256 Prime
    p: BigInt,
    /// Slave's share of PMS
    secret: BigInt,
    /// Masks
    masks: Masks,
    // Slave's secret point's coordinates
    x: BigInt,
    y: BigInt,
    /// Master's Paillier encryption key
    enc_key: Option<EncryptionKey>,
    /// E(-x_p)
    e_neg_x_p: Option<BigInt>,
    /// E(-x_q)
    e_neg_x_q: Option<BigInt>,
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

#[derive(PartialEq, Debug)]
pub struct S1 {
    /// N_A mod p
    pub(crate) n_a_mod_p: BigInt,
    /// N_T mod p
    pub(crate) n_t_mod_p: BigInt,
    /// E(A * M_A + N_A)
    pub(crate) e_a_masked: BigInt,
    /// E(T * M_T + N_T)
    pub(crate) e_t_masked: BigInt,
}

#[derive(PartialEq, Debug)]
pub struct S2 {
    /// N_B mod p
    pub(crate) n_b_mod_p: BigInt,
    /// E(B * M_C + N_C)
    pub(crate) e_b_masked: BigInt,
}

#[derive(PartialEq, Debug)]
pub struct S3 {
    /// E(PMS + S_q)
    pub(crate) e_pms_masked: BigInt,
}

impl SlaveCore for PointAdditionSlave {
    fn next(
        &mut self,
        message: Option<PointAdditionMessage>,
    ) -> Result<Option<PointAdditionMessage>, PointAdditionError> {
        let message = match (self.state, message) {
            (State::Initialized, Some(PointAdditionMessage::M1(m))) => {
                self.state = State::S1;
                Some(PointAdditionMessage::S1(self.step1(m)))
            }
            (State::S1, Some(PointAdditionMessage::M2(m))) => {
                self.state = State::S2;
                Some(PointAdditionMessage::S2(self.step2(m)))
            }
            (State::S2, Some(PointAdditionMessage::M3(m))) => {
                self.state = State::Complete;
                Some(PointAdditionMessage::S3(self.step3(m)))
            }
            (state, message) => Err(PointAdditionError::ProtocolError(Box::new(state), message))?,
        };
        Ok(message)
    }

    fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn get_secret(self) -> Result<SecretShare, PointAdditionError> {
        Ok(&self.p - (self.secret % &self.p))
    }
}

impl PointAdditionSlave {
    pub fn new(point: &EncodedPoint) -> Self {
        Self {
            x: BigInt::from_bytes(point.x().expect("Invalid point")),
            y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
            p: BigInt::from_hex(P).unwrap(),
            masks: Masks::generate(),
            secret: BigInt::sample(1027),
            state: State::Initialized,
            enc_key: None,
            e_neg_x_p: None,
            e_neg_x_q: None,
        }
    }

    pub fn from_secret(point: EncodedPoint, secret: BigInt) -> Self {
        Self {
            x: BigInt::from_bytes(point.x().expect("Invalid point")),
            y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
            p: BigInt::from_hex(P).unwrap(),
            masks: Masks::generate(),
            secret,
            state: State::Initialized,
            enc_key: None,
            e_neg_x_p: None,
            e_neg_x_q: None,
        }
    }

    fn step1(&mut self, m: M1) -> S1 {
        // Computes E(T) = E(x_q - x_p)
        let e_x_q: RawCiphertext = m.e_x_q.into();
        let e_neg_x_p = Paillier::encrypt(
            &m.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.p, &self.x, &self.p)),
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
            RawPlaintext::from(BigInt::mod_pow(&self.y, &BigInt::from(2_u16), &self.p)),
        );
        let e_y_pq_pow_2 = Paillier::add(&m.enc_key, e_y_p_pow_2, e_y_q_pow_2);
        let e_neg_2_y_q_y_p = Paillier::mul(&m.enc_key, e_neg_2_y_q, RawPlaintext::from(&self.y));
        let e_a = Paillier::add(&m.enc_key, e_y_pq_pow_2, e_neg_2_y_q_y_p);

        // Computes E(A * M_A + N_A)
        let e_a_m_a = Paillier::mul(&m.enc_key, e_a, RawPlaintext::from(&self.masks.m_a));
        let e_n_a = Paillier::encrypt(&m.enc_key, RawPlaintext::from(&self.masks.n_a));
        let e_a_masked = Paillier::add(&m.enc_key, e_a_m_a, e_n_a);

        let e_a_masked: BigInt = Paillier::rerandomize(&m.enc_key, e_a_masked).into();
        let e_t_masked: BigInt = Paillier::rerandomize(&m.enc_key, e_t_masked).into();

        self.enc_key = Some(m.enc_key);
        self.e_neg_x_q = Some(m.e_neg_x_q);
        self.e_neg_x_p = Some(BigInt::from(e_neg_x_p));

        S1 {
            n_a_mod_p: &self.masks.n_a % &self.p,
            n_t_mod_p: &self.masks.n_t % &self.p,
            e_a_masked,
            e_t_masked,
        }
    }

    fn step2(&mut self, m: M2) -> S2 {
        // Computes E(B) = E((T * M_T)^p-3 mod p) * (M_T^p-3)^-1 mod p
        let inv = BigInt::mod_inv(
            &BigInt::mod_pow(&self.masks.m_t, &(&self.p - 3), &self.p),
            &self.p,
        )
        .unwrap();
        let enc_key = self.enc_key.as_ref().unwrap();
        let e_b = Paillier::mul(
            enc_key,
            RawCiphertext::from(m.e_t_mod_pow),
            RawPlaintext::from(inv),
        );

        // Computes E(B * M_C + N_C)
        let e_b_m_b = Paillier::mul(enc_key, e_b, RawPlaintext::from(&self.masks.m_b));
        let e_n_b = Paillier::encrypt(enc_key, RawPlaintext::from(&self.masks.n_b));
        let e_b_masked = Paillier::add(enc_key, e_b_m_b, e_n_b);

        S2 {
            n_b_mod_p: &self.masks.n_b % &self.p,
            e_b_masked: Paillier::rerandomize(enc_key, e_b_masked).into(),
        }
    }

    fn step3(&mut self, m: M3) -> S3 {
        // Computes E(A * B)
        let inv = BigInt::mod_inv(
            &BigInt::mod_mul(&self.masks.m_a, &self.masks.m_b, &self.p),
            &self.p,
        )
        .unwrap();
        let enc_key = self.enc_key.as_ref().unwrap();
        let e_a_b = Paillier::mul(
            enc_key,
            RawCiphertext::from(m.e_ab_masked),
            RawPlaintext::from(inv),
        );

        // Computes E(PMS + S_q)
        let e_pms = Paillier::add(
            enc_key,
            Paillier::add(
                enc_key,
                e_a_b,
                RawCiphertext::from(self.e_neg_x_q.as_ref().unwrap()),
            ),
            RawCiphertext::from(self.e_neg_x_p.as_ref().unwrap()),
        );
        let e_secret = Paillier::encrypt(enc_key, RawPlaintext::from(&self.secret));
        let e_pms_masked = Paillier::add(enc_key, e_pms, e_secret);

        S3 {
            e_pms_masked: Paillier::rerandomize(enc_key, e_pms_masked).into(),
        }
    }
}
