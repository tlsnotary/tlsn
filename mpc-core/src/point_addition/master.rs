use super::{errors::*, MasterCore, SecretShare, P};
use crate::msgs::point_addition as msgs;
use curv::arithmetic::{Converter, Modulo};
use p256::EncodedPoint;
use paillier::*;

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    Initialized,
    M1,
    M2,
    M3,
    Complete,
}

pub struct PointAdditionMaster {
    /// NIST P-256 Prime
    p: BigInt,
    /// Current state of secret share protocol
    state: State,
    /// Master's Paillier encryption key
    enc_key: EncryptionKey,
    /// Master's Paillier decryption key
    dec_key: DecryptionKey,
    /// X coordinate of master's secret
    x: BigInt,
    /// Y coordinate of master's secret
    y: BigInt,
    /// temp value stored between communication rounds
    a_masked_mod_p: Option<BigInt>,
    /// Master's share of PMS
    secret: Option<BigInt>,
}

impl MasterCore for PointAdditionMaster {
    fn next(
        &mut self,
        message: Option<msgs::PointAdditionMessage>,
    ) -> Result<Option<msgs::PointAdditionMessage>, PointAdditionError> {
        let message = match (self.state, message) {
            (State::Initialized, None) => {
                self.state = State::M1;
                Some(msgs::PointAdditionMessage::M1(self.step1()))
            }
            (State::M1, Some(msgs::PointAdditionMessage::S1(s))) => {
                self.state = State::M2;
                Some(msgs::PointAdditionMessage::M2(self.step2(s)))
            }
            (State::M2, Some(msgs::PointAdditionMessage::S2(s))) => {
                self.state = State::M3;
                Some(msgs::PointAdditionMessage::M3(self.step3(s)))
            }
            (State::M3, Some(msgs::PointAdditionMessage::S3(s))) => {
                self.state = State::Complete;
                self.step4(s);
                None
            }
            (state, message) => Err(PointAdditionError::ProtocolError(Box::new(state), message))?,
        };
        Ok(message)
    }

    fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn get_secret(self) -> Result<SecretShare, PointAdditionError> {
        Ok(self.secret.ok_or(PointAdditionError::ProtocolIncomplete)?)
    }
}

impl PointAdditionMaster {
    pub fn new(point: &EncodedPoint) -> Self {
        let (enc_key, dec_key) = Paillier::keypair().keys();
        Self {
            x: BigInt::from_bytes(point.x().expect("Invalid point")),
            y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
            p: BigInt::from_hex(P).unwrap(),
            enc_key,
            dec_key,
            state: State::Initialized,
            a_masked_mod_p: None,
            secret: None,
        }
    }

    fn step1(&mut self) -> msgs::M1 {
        // Computes E(x_q)
        let e_x_q: BigInt = Paillier::encrypt(&self.enc_key, RawPlaintext::from(&self.x)).into();

        // Computes E(-x_q)
        let e_neg_x_q: BigInt = Paillier::encrypt(
            &self.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.p, &self.x, &self.p)),
        )
        .into();

        // Computes E(y_q^2)
        let e_y_q_pow_2: BigInt = Paillier::encrypt(
            &self.enc_key,
            RawPlaintext::from(BigInt::mod_pow(&self.y, &BigInt::from(2_u16), &self.p)),
        )
        .into();

        // Computes E(-2y_q)
        let e_neg_2_y_q: BigInt = Paillier::encrypt(
            &self.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.p, &(2 * &self.y), &self.p)),
        )
        .into();

        msgs::M1 {
            enc_key: self.enc_key.clone(),
            e_x_q,
            e_neg_x_q,
            e_y_q_pow_2,
            e_neg_2_y_q,
        }
    }

    fn step2(&mut self, s: msgs::S1) -> msgs::M2 {
        // Computes A * M_A mod p
        let a_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_a_masked)).into();
        let a_masked_mod_p = BigInt::mod_sub(&a_masked, &s.n_a_mod_p, &self.p);

        // Computes T * M_T mod p
        let t_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_t_masked)).into();
        let t_masked_mod_p = BigInt::mod_sub(&t_masked, &s.n_t_mod_p, &self.p);

        // Computes E((T * M_T)^p-3 mod p)
        let t_mod_pow = BigInt::mod_pow(&t_masked_mod_p, &(&self.p - 3), &self.p);
        let e_t_mod_pow: BigInt =
            Paillier::encrypt(&self.enc_key, RawPlaintext::from(t_mod_pow)).into();
        self.a_masked_mod_p = Some(a_masked_mod_p);

        msgs::M2 { e_t_mod_pow }
    }

    fn step3(&mut self, s: msgs::S2) -> msgs::M3 {
        // Computes B * M_B mod p
        let b_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_b_masked)).into();
        let b_masked_mod_p = BigInt::mod_sub(&b_masked, &s.n_b_mod_p, &self.p);

        // Computes E(A * M_A * B * M_B)
        let e_ab_masked: BigInt = Paillier::encrypt(
            &self.enc_key,
            RawPlaintext::from(BigInt::mod_mul(
                &b_masked_mod_p,
                self.a_masked_mod_p.as_ref().unwrap(),
                &self.p,
            )),
        )
        .into();

        msgs::M3 { e_ab_masked }
    }

    fn step4(&mut self, s: msgs::S3) {
        // Computes master's secret, s_p
        let pms_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_pms_masked)).into();
        self.secret = Some(pms_masked % &self.p);
    }
}
