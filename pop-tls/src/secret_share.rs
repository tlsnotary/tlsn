//! 2-Party Elliptic curve secret-sharing using Paillier Cryptosystem

use curv::arithmetic::{Converter, Modulo, Samplable};
use p256::EncodedPoint;
use paillier::*;

/// NIST P-256 Prime
const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

#[derive(Clone, Debug, PartialEq, PartialOrd)]
enum State {
    Initialized,
    StepOne,
    StepTwo,
    StepThree,
}

pub struct SecretShareMaster {
    /// NIST P-256 Prime
    p: BigInt,
    /// X coordinate of master's secret
    x: BigInt,
    /// Y coordinate of master's secret
    y: BigInt,
    /// Current state of secret share protocol
    state: State,
    /// Master's Paillier encryption key
    enc_key: EncryptionKey,
    /// Master's Paillier decryption key
    dec_key: DecryptionKey,
    /// Cached values used in protocol
    cache: MasterCache,
}

pub struct MasterCache {
    /// A * M_A mod p
    a_masked_mod_p: Option<BigInt>,
}

pub struct MasterStepOne {
    /// Master's encryption key
    enc_key: EncryptionKey,
    /// E(x_q)
    e_x_q: BigInt,
    /// E(-x_q)
    e_neg_x_q: BigInt,
    /// E(y_q^2)
    e_y_q_pow_2: BigInt,
    /// E(-2y_q)
    e_neg_2_y_q: BigInt,
}

pub struct MasterStepTwo {
    /// E((T * M_T)^p-3 mod p)
    e_t_mod_pow: BigInt,
}

pub struct MasterStepThree {
    /// E(A * M_A * B * M_B)
    e_ab_masked: BigInt,
}

impl SecretShareMaster {
    pub fn new(point: EncodedPoint) -> Self {
        let (enc_key, dec_key) = Paillier::keypair().keys();
        Self {
            p: BigInt::from_hex(P).unwrap(),
            x: BigInt::from_bytes(point.x().expect("Invalid point")),
            y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
            enc_key,
            dec_key,
            state: State::Initialized,
            cache: MasterCache {
                a_masked_mod_p: None,
            },
        }
    }

    pub fn step_one(&self) -> MasterStepOne {
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
            RawPlaintext::from(BigInt::mod_pow(&self.y, &BigInt::from(2), &self.p)),
        )
        .into();

        // Computes E(-2y_q)
        let e_neg_2_y_q: BigInt = Paillier::encrypt(
            &self.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.p, &(2 * &self.y), &self.p)),
        )
        .into();

        MasterStepOne {
            enc_key: self.enc_key.clone(),
            e_x_q,
            e_neg_x_q,
            e_y_q_pow_2,
            e_neg_2_y_q,
        }
    }

    pub fn step_two(&mut self, s: SlaveStepOne) -> MasterStepTwo {
        // Computes A * M_A mod p
        let a_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_a_masked)).into();
        let a_masked_mod_p = BigInt::mod_sub(&a_masked, &s.n_a_mod_p, &self.p);

        self.cache.a_masked_mod_p = Some(a_masked_mod_p);

        // Computes T * M_T mod p
        let t_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_t_masked)).into();
        let t_masked_mod_p = BigInt::mod_sub(&t_masked, &s.n_t_mod_p, &self.p);

        // Computes E((T * M_T)^p-3 mod p)
        let t_mod_pow = BigInt::mod_pow(&t_masked_mod_p, &(&self.p - 3), &self.p);
        let e_t_mod_pow: BigInt =
            Paillier::encrypt(&self.enc_key, RawPlaintext::from(t_mod_pow)).into();

        MasterStepTwo { e_t_mod_pow }
    }

    pub fn step_three(&mut self, s: SlaveStepTwo) -> MasterStepThree {
        // Computes B * M_B mod p
        let b_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_b_masked)).into();
        let b_masked_mod_p = BigInt::mod_sub(&b_masked, &s.n_b_mod_p, &self.p);

        // Computes E(A * M_A * B * M_B)
        let a_masked_mod_p = self.cache.a_masked_mod_p.as_ref().unwrap();
        let e_ab_masked: BigInt = Paillier::encrypt(
            &self.enc_key,
            RawPlaintext::from(BigInt::mod_mul(&b_masked_mod_p, &a_masked_mod_p, &self.p)),
        )
        .into();

        MasterStepThree { e_ab_masked }
    }

    pub fn step_four(&self, s: SlaveStepThree) -> BigInt {
        // Computes master's secret, s_p
        let pms_masked: BigInt =
            Paillier::decrypt(&self.dec_key, RawCiphertext::from(s.e_pms_masked)).into();
        pms_masked % &self.p
    }
}

pub struct SecretShareSlave {
    /// NIST P-256 Prime
    p: BigInt,
    /// X coordinate of slave's secret
    x: BigInt,
    /// Y coordinate of slave's secret
    y: BigInt,
    /// Current state of secret share protocol
    state: State,
    /// Cached values used during protocol
    cache: SlaveCache,
    /// Slave's share of PMS
    secret: BigInt,
}

struct SlaveCache {
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

    /// Master's Paillier encryption key
    enc_key: Option<EncryptionKey>,
    /// E(-x_p)
    e_neg_x_p: Option<BigInt>,
    /// E(-x_q)
    e_neg_x_q: Option<BigInt>,
}

pub struct SlaveStepOne {
    /// N_A mod_p
    n_a_mod_p: BigInt,
    /// N_b mod p
    n_t_mod_p: BigInt,
    /// E(A * M_A + N_A)
    e_a_masked: BigInt,
    /// E(T * M_T + N_T)
    e_t_masked: BigInt,
}

pub struct SlaveStepTwo {
    /// N_C mod p
    n_b_mod_p: BigInt,
    /// E(B * M_C + N_C)
    e_b_masked: BigInt,
}

pub struct SlaveStepThree {
    /// E(PMS + S_q)
    e_pms_masked: BigInt,
}

impl SecretShareSlave {
    pub fn new(point: EncodedPoint) -> Self {
        Self {
            p: BigInt::from_hex(P).unwrap(),
            x: BigInt::from_bytes(point.x().expect("Invalid point")),
            y: BigInt::from_bytes(point.y().expect("Invalid point, or compressed")),
            state: State::Initialized,
            cache: SlaveCache {
                n_a: BigInt::sample(1024),
                n_t: BigInt::sample(512),
                n_b: BigInt::sample(1024),
                m_a: BigInt::sample(512),
                m_t: BigInt::sample(256),
                m_b: BigInt::sample(512),
                enc_key: None,
                e_neg_x_p: None,
                e_neg_x_q: None,
            },
            secret: BigInt::sample(1027),
        }
    }

    pub fn secret(&self) -> BigInt {
        &self.p - (&self.secret % &self.p)
    }

    pub fn step_one(&mut self, m: MasterStepOne) -> SlaveStepOne {
        // Computes E(T) = E(x_q - x_p)
        let e_x_q: RawCiphertext = m.e_x_q.into();
        let e_neg_x_p = Paillier::encrypt(
            &m.enc_key,
            RawPlaintext::from(BigInt::mod_sub(&self.p, &self.x, &self.p)),
        );
        let e_t = Paillier::add(&m.enc_key, e_x_q, e_neg_x_p.clone());

        self.cache.e_neg_x_p = Some(BigInt::from(e_neg_x_p));

        // Computes E(T * M_T + N_T)
        let e_n_t = Paillier::encrypt(&m.enc_key, RawPlaintext::from(&self.cache.n_t));
        let e_t_m_t = Paillier::mul(&m.enc_key, e_t, RawPlaintext::from(&self.cache.m_t));
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
        let e_a_m_a = Paillier::mul(&m.enc_key, e_a, RawPlaintext::from(&self.cache.m_a));
        let e_n_a = Paillier::encrypt(&m.enc_key, RawPlaintext::from(&self.cache.n_a));
        let e_a_masked = Paillier::add(&m.enc_key, e_a_m_a, e_n_a);

        let e_a_masked: BigInt = Paillier::rerandomize(&m.enc_key, e_a_masked).into();
        let e_t_masked: BigInt = Paillier::rerandomize(&m.enc_key, e_t_masked).into();

        self.cache.enc_key = Some(m.enc_key);
        self.cache.e_neg_x_q = Some(m.e_neg_x_q);

        SlaveStepOne {
            n_a_mod_p: &self.cache.n_a % &self.p,
            n_t_mod_p: &self.cache.n_t % &self.p,
            e_a_masked,
            e_t_masked,
        }
    }

    pub fn step_two(&mut self, m: MasterStepTwo) -> SlaveStepTwo {
        let enc_key = self.cache.enc_key.as_ref().unwrap();

        // Computes E(B) = E((T * M_T)^p-3 mod p) * (M_T^p-3)^-1 mod p
        let inv = BigInt::mod_inv(
            &BigInt::mod_pow(&self.cache.m_t, &(&self.p - 3), &self.p),
            &self.p,
        )
        .unwrap();
        let e_b = Paillier::mul(
            enc_key,
            RawCiphertext::from(m.e_t_mod_pow),
            RawPlaintext::from(inv),
        );

        // Computes E(B * M_C + N_C)
        let e_b_m_b = Paillier::mul(enc_key, e_b, RawPlaintext::from(&self.cache.m_b));
        let e_n_b = Paillier::encrypt(enc_key, RawPlaintext::from(&self.cache.n_b));
        let e_b_masked = Paillier::add(enc_key, e_b_m_b, e_n_b);

        SlaveStepTwo {
            n_b_mod_p: &self.cache.n_b % &self.p,
            e_b_masked: Paillier::rerandomize(enc_key, e_b_masked).into(),
        }
    }

    pub fn step_three(&mut self, m: MasterStepThree) -> SlaveStepThree {
        let enc_key = self.cache.enc_key.as_ref().unwrap();

        // Computes E(A * B)
        let inv = BigInt::mod_inv(
            &BigInt::mod_mul(&self.cache.m_a, &self.cache.m_b, &self.p),
            &self.p,
        )
        .unwrap();
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
                RawCiphertext::from(self.cache.e_neg_x_q.as_ref().unwrap()),
            ),
            RawCiphertext::from(self.cache.e_neg_x_p.as_ref().unwrap()),
        );
        let e_secret = Paillier::encrypt(enc_key, RawPlaintext::from(&self.secret));
        let e_pms_masked = Paillier::add(enc_key, e_pms, e_secret);

        SlaveStepThree {
            e_pms_masked: Paillier::rerandomize(enc_key, e_pms_masked).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand::thread_rng;

    #[test]
    fn test() {
        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let master_secret = SecretKey::random(&mut rng);
        let master_point =
            (&server_pk * &master_secret.to_nonzero_scalar()).to_encoded_point(false);

        let slave_secret = SecretKey::random(&mut rng);
        let slave_point = (&server_pk * &slave_secret.to_nonzero_scalar()).to_encoded_point(false);

        let mut master = SecretShareMaster::new(master_point);
        let mut slave = SecretShareSlave::new(slave_point);

        let master_step_one = master.step_one();
        let slave_step_one = slave.step_one(master_step_one);
        let master_step_two = master.step_two(slave_step_one);
        let slave_step_two = slave.step_two(master_step_two);
        let master_step_three = master.step_three(slave_step_two);
        let slave_step_three = slave.step_three(master_step_three);
        let master_share = master.step_four(slave_step_three);
        let slave_share = slave.secret();

        let pms = ((&server_pk * &master_secret.to_nonzero_scalar())
            + (&server_pk * &slave_secret.to_nonzero_scalar()))
            .to_affine();
        let pms = BigInt::from_bytes(pms.to_encoded_point(false).x().unwrap());

        assert_eq!(pms, (master_share + slave_share));
    }
}
