use paillier::{BigInt, EncryptionKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PointAdditionMessage {
    M1(M1),
    M2(M2),
    M3(M3),
    S1(S1),
    S2(S2),
    S3(S3),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M1 {
    /// Master's encryption key
    pub enc_key: EncryptionKey,
    /// E(x_q)
    pub e_x_q: BigInt,
    /// E(-x_q)
    pub e_neg_x_q: BigInt,
    /// E(y_q^2)
    pub e_y_q_pow_2: BigInt,
    /// E(-2y_q)
    pub e_neg_2_y_q: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M2 {
    /// E((T * M_T)^p-3 mod p)
    pub e_t_mod_pow: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M3 {
    /// E(A * M_A * B * M_B)
    pub e_ab_masked: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S1 {
    /// N_A mod p
    pub n_a_mod_p: BigInt,
    /// N_T mod p
    pub n_t_mod_p: BigInt,
    /// E(A * M_A + N_A)
    pub e_a_masked: BigInt,
    /// E(T * M_T + N_T)
    pub e_t_masked: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S2 {
    /// N_B mod p
    pub n_b_mod_p: BigInt,
    /// E(B * M_C + N_C)
    pub e_b_masked: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3 {
    /// E(PMS + S_q)
    pub e_pms_masked: BigInt,
}

#[cfg(feature = "proto")]
mod proto {
    use super::*;
    use crate::proto::point_addition as proto;
    use curv::{arithmetic::Converter, BigInt};
    use std::convert::TryFrom;

    pub use proto::point_addition_message::Msg;

    impl From<paillier::EncryptionKey> for proto::EncryptionKey {
        #[inline]
        fn from(k: paillier::EncryptionKey) -> Self {
            Self {
                n: k.n.to_bytes(),
                nn: k.nn.to_bytes(),
            }
        }
    }

    impl From<proto::EncryptionKey> for paillier::EncryptionKey {
        #[inline]
        fn from(k: proto::EncryptionKey) -> Self {
            Self {
                n: BigInt::from_bytes(k.n.as_slice()),
                nn: BigInt::from_bytes(k.nn.as_slice()),
            }
        }
    }

    impl From<PointAdditionMessage> for proto::PointAdditionMessage {
        #[inline]
        fn from(m: PointAdditionMessage) -> Self {
            Self {
                msg: Some(match m {
                    PointAdditionMessage::M1(msg) => Msg::M1(proto::M1::from(msg)),
                    PointAdditionMessage::M2(msg) => Msg::M2(proto::M2::from(msg)),
                    PointAdditionMessage::M3(msg) => Msg::M3(proto::M3::from(msg)),
                    PointAdditionMessage::S1(msg) => Msg::S1(proto::S1::from(msg)),
                    PointAdditionMessage::S2(msg) => Msg::S2(proto::S2::from(msg)),
                    PointAdditionMessage::S3(msg) => Msg::S3(proto::S3::from(msg)),
                }),
            }
        }
    }

    impl TryFrom<proto::PointAdditionMessage> for PointAdditionMessage {
        type Error = std::io::Error;
        #[inline]
        fn try_from(m: proto::PointAdditionMessage) -> Result<Self, Self::Error> {
            if let Some(msg) = m.msg {
                let m = match msg {
                    Msg::M1(msg) => PointAdditionMessage::M1(M1::from(msg)),
                    Msg::M2(msg) => PointAdditionMessage::M2(M2::from(msg)),
                    Msg::M3(msg) => PointAdditionMessage::M3(M3::from(msg)),
                    Msg::S1(msg) => PointAdditionMessage::S1(S1::from(msg)),
                    Msg::S2(msg) => PointAdditionMessage::S2(S2::from(msg)),
                    Msg::S3(msg) => PointAdditionMessage::S3(S3::from(msg)),
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

    impl From<M1> for proto::M1 {
        #[inline]
        fn from(m: M1) -> Self {
            Self {
                enc_key: m.enc_key.into(),
                e_x_q: m.e_x_q.to_bytes(),
                e_neg_x_q: m.e_neg_x_q.to_bytes(),
                e_y_q_pow_2: m.e_y_q_pow_2.to_bytes(),
                e_neg_2_y_q: m.e_neg_2_y_q.to_bytes(),
            }
        }
    }

    impl From<proto::M1> for M1 {
        #[inline]
        fn from(m: proto::M1) -> Self {
            Self {
                enc_key: m.enc_key.into(),
                e_x_q: BigInt::from_bytes(m.e_x_q.as_slice()),
                e_neg_x_q: BigInt::from_bytes(m.e_neg_x_q.as_slice()),
                e_y_q_pow_2: BigInt::from_bytes(m.e_y_q_pow_2.as_slice()),
                e_neg_2_y_q: BigInt::from_bytes(m.e_neg_2_y_q.as_slice()),
            }
        }
    }

    impl From<M2> for proto::M2 {
        #[inline]
        fn from(m: M2) -> Self {
            Self {
                e_t_mod_pow: m.e_t_mod_pow.to_bytes(),
            }
        }
    }

    impl From<proto::M2> for M2 {
        #[inline]
        fn from(m: proto::M2) -> Self {
            Self {
                e_t_mod_pow: BigInt::from_bytes(m.e_t_mod_pow.as_slice()),
            }
        }
    }

    impl From<M3> for proto::M3 {
        #[inline]
        fn from(m: M3) -> Self {
            Self {
                e_ab_masked: m.e_ab_masked.to_bytes(),
            }
        }
    }

    impl From<proto::M3> for M3 {
        #[inline]
        fn from(m: proto::M3) -> Self {
            Self {
                e_ab_masked: BigInt::from_bytes(m.e_ab_masked.as_slice()),
            }
        }
    }

    impl From<S1> for proto::S1 {
        #[inline]
        fn from(m: S1) -> Self {
            Self {
                n_a_mod_p: m.n_a_mod_p.to_bytes(),
                n_t_mod_p: m.n_t_mod_p.to_bytes(),
                e_a_masked: m.e_a_masked.to_bytes(),
                e_t_masked: m.e_t_masked.to_bytes(),
            }
        }
    }

    impl From<proto::S1> for S1 {
        #[inline]
        fn from(m: proto::S1) -> Self {
            Self {
                n_a_mod_p: BigInt::from_bytes(m.n_a_mod_p.as_slice()),
                n_t_mod_p: BigInt::from_bytes(m.n_t_mod_p.as_slice()),
                e_a_masked: BigInt::from_bytes(m.e_a_masked.as_slice()),
                e_t_masked: BigInt::from_bytes(m.e_t_masked.as_slice()),
            }
        }
    }

    impl From<S2> for proto::S2 {
        #[inline]
        fn from(m: S2) -> Self {
            Self {
                n_b_mod_p: m.n_b_mod_p.to_bytes(),
                e_b_masked: m.e_b_masked.to_bytes(),
            }
        }
    }

    impl From<proto::S2> for S2 {
        #[inline]
        fn from(m: proto::S2) -> Self {
            Self {
                n_b_mod_p: BigInt::from_bytes(m.n_b_mod_p.as_slice()),
                e_b_masked: BigInt::from_bytes(m.e_b_masked.as_slice()),
            }
        }
    }

    impl From<S3> for proto::S3 {
        #[inline]
        fn from(m: S3) -> Self {
            Self {
                e_pms_masked: m.e_pms_masked.to_bytes(),
            }
        }
    }

    impl From<proto::S3> for S3 {
        #[inline]
        fn from(m: proto::S3) -> Self {
            Self {
                e_pms_masked: BigInt::from_bytes(m.e_pms_masked.as_slice()),
            }
        }
    }
}

#[cfg(feature = "proto")]
pub use proto::*;
