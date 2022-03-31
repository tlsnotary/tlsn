use crate::secret_share;
use crate::secret_share::{master, slave};
use curv::{arithmetic::Converter, BigInt};
use std::convert::TryFrom;

include!(concat!(env!("OUT_DIR"), "/core.secret_share.rs"));

pub use secret_share_message::Msg;

impl From<paillier::EncryptionKey> for EncryptionKey {
    #[inline]
    fn from(k: paillier::EncryptionKey) -> Self {
        Self {
            n: k.n.to_bytes(),
            nn: k.nn.to_bytes(),
        }
    }
}

impl From<EncryptionKey> for paillier::EncryptionKey {
    #[inline]
    fn from(k: EncryptionKey) -> Self {
        Self {
            n: BigInt::from_bytes(k.n.as_slice()),
            nn: BigInt::from_bytes(k.nn.as_slice()),
        }
    }
}

impl From<secret_share::SecretShareMessage> for SecretShareMessage {
    #[inline]
    fn from(m: secret_share::SecretShareMessage) -> Self {
        Self {
            msg: Some(match m {
                secret_share::SecretShareMessage::M1(msg) => {
                    secret_share_message::Msg::M1(M1::from(msg))
                }
                secret_share::SecretShareMessage::M2(msg) => {
                    secret_share_message::Msg::M2(M2::from(msg))
                }
                secret_share::SecretShareMessage::M3(msg) => {
                    secret_share_message::Msg::M3(M3::from(msg))
                }
                secret_share::SecretShareMessage::S1(msg) => {
                    secret_share_message::Msg::S1(S1::from(msg))
                }
                secret_share::SecretShareMessage::S2(msg) => {
                    secret_share_message::Msg::S2(S2::from(msg))
                }
                secret_share::SecretShareMessage::S3(msg) => {
                    secret_share_message::Msg::S3(S3::from(msg))
                }
            }),
        }
    }
}

impl TryFrom<SecretShareMessage> for secret_share::SecretShareMessage {
    type Error = std::io::Error;
    #[inline]
    fn try_from(m: SecretShareMessage) -> Result<Self, Self::Error> {
        if let Some(msg) = m.msg {
            let m = match msg {
                secret_share_message::Msg::M1(msg) => {
                    secret_share::SecretShareMessage::M1(master::M1::from(msg))
                }
                secret_share_message::Msg::M2(msg) => {
                    secret_share::SecretShareMessage::M2(master::M2::from(msg))
                }
                secret_share_message::Msg::M3(msg) => {
                    secret_share::SecretShareMessage::M3(master::M3::from(msg))
                }
                secret_share_message::Msg::S1(msg) => {
                    secret_share::SecretShareMessage::S1(slave::S1::from(msg))
                }
                secret_share_message::Msg::S2(msg) => {
                    secret_share::SecretShareMessage::S2(slave::S2::from(msg))
                }
                secret_share_message::Msg::S3(msg) => {
                    secret_share::SecretShareMessage::S3(slave::S3::from(msg))
                }
            };
            Ok(m)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Malformed message: {:?}", m),
            ))
        }
    }
}

impl From<master::M1> for M1 {
    #[inline]
    fn from(m: master::M1) -> Self {
        Self {
            enc_key: m.enc_key.into(),
            e_x_q: m.e_x_q.to_bytes(),
            e_neg_x_q: m.e_neg_x_q.to_bytes(),
            e_y_q_pow_2: m.e_y_q_pow_2.to_bytes(),
            e_neg_2_y_q: m.e_neg_2_y_q.to_bytes(),
        }
    }
}

impl From<M1> for master::M1 {
    #[inline]
    fn from(m: M1) -> Self {
        Self {
            enc_key: m.enc_key.into(),
            e_x_q: BigInt::from_bytes(m.e_x_q.as_slice()),
            e_neg_x_q: BigInt::from_bytes(m.e_neg_x_q.as_slice()),
            e_y_q_pow_2: BigInt::from_bytes(m.e_y_q_pow_2.as_slice()),
            e_neg_2_y_q: BigInt::from_bytes(m.e_neg_2_y_q.as_slice()),
        }
    }
}

impl From<master::M2> for M2 {
    #[inline]
    fn from(m: master::M2) -> Self {
        Self {
            e_t_mod_pow: m.e_t_mod_pow.to_bytes(),
        }
    }
}

impl From<M2> for master::M2 {
    #[inline]
    fn from(m: M2) -> Self {
        Self {
            e_t_mod_pow: BigInt::from_bytes(m.e_t_mod_pow.as_slice()),
        }
    }
}

impl From<master::M3> for M3 {
    #[inline]
    fn from(m: master::M3) -> Self {
        Self {
            e_ab_masked: m.e_ab_masked.to_bytes(),
        }
    }
}

impl From<M3> for master::M3 {
    #[inline]
    fn from(m: M3) -> Self {
        Self {
            e_ab_masked: BigInt::from_bytes(m.e_ab_masked.as_slice()),
        }
    }
}

impl From<slave::S1> for S1 {
    #[inline]
    fn from(m: slave::S1) -> Self {
        Self {
            n_a_mod_p: m.n_a_mod_p.to_bytes(),
            n_t_mod_p: m.n_t_mod_p.to_bytes(),
            e_a_masked: m.e_a_masked.to_bytes(),
            e_t_masked: m.e_t_masked.to_bytes(),
        }
    }
}

impl From<S1> for slave::S1 {
    #[inline]
    fn from(m: S1) -> Self {
        Self {
            n_a_mod_p: BigInt::from_bytes(m.n_a_mod_p.as_slice()),
            n_t_mod_p: BigInt::from_bytes(m.n_t_mod_p.as_slice()),
            e_a_masked: BigInt::from_bytes(m.e_a_masked.as_slice()),
            e_t_masked: BigInt::from_bytes(m.e_t_masked.as_slice()),
        }
    }
}

impl From<slave::S2> for S2 {
    #[inline]
    fn from(m: slave::S2) -> Self {
        Self {
            n_b_mod_p: m.n_b_mod_p.to_bytes(),
            e_b_masked: m.e_b_masked.to_bytes(),
        }
    }
}

impl From<S2> for slave::S2 {
    #[inline]
    fn from(m: S2) -> Self {
        Self {
            n_b_mod_p: BigInt::from_bytes(m.n_b_mod_p.as_slice()),
            e_b_masked: BigInt::from_bytes(m.e_b_masked.as_slice()),
        }
    }
}

impl From<slave::S3> for S3 {
    #[inline]
    fn from(m: slave::S3) -> Self {
        Self {
            e_pms_masked: m.e_pms_masked.to_bytes(),
        }
    }
}

impl From<S3> for slave::S3 {
    #[inline]
    fn from(m: S3) -> Self {
        Self {
            e_pms_masked: BigInt::from_bytes(m.e_pms_masked.as_slice()),
        }
    }
}
