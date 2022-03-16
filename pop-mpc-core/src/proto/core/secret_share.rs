use super::super::errors::ProtoError;
use crate::secret_share::{master, slave};
use curv::{arithmetic::Converter, BigInt};

include!(concat!(env!("OUT_DIR"), "/core.secret_share.rs"));

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

impl From<master::MasterStepOne> for MasterStepOne {
    #[inline]
    fn from(m: master::MasterStepOne) -> Self {
        Self {
            enc_key: m.enc_key.into(),
            e_x_q: m.e_x_q.to_bytes(),
            e_neg_x_q: m.e_neg_x_q.to_bytes(),
            e_y_q_pow_2: m.e_y_q_pow_2.to_bytes(),
            e_neg_2_y_q: m.e_neg_2_y_q.to_bytes(),
        }
    }
}

impl From<MasterStepOne> for master::MasterStepOne {
    #[inline]
    fn from(m: MasterStepOne) -> Self {
        Self {
            enc_key: m.enc_key.into(),
            e_x_q: BigInt::from_bytes(m.e_x_q.as_slice()),
            e_neg_x_q: BigInt::from_bytes(m.e_neg_x_q.as_slice()),
            e_y_q_pow_2: BigInt::from_bytes(m.e_y_q_pow_2.as_slice()),
            e_neg_2_y_q: BigInt::from_bytes(m.e_neg_2_y_q.as_slice()),
        }
    }
}

impl From<master::MasterStepTwo> for MasterStepTwo {
    #[inline]
    fn from(m: master::MasterStepTwo) -> Self {
        Self {
            e_t_mod_pow: m.e_t_mod_pow.to_bytes(),
        }
    }
}

impl From<MasterStepTwo> for master::MasterStepTwo {
    #[inline]
    fn from(m: MasterStepTwo) -> Self {
        Self {
            e_t_mod_pow: BigInt::from_bytes(m.e_t_mod_pow.as_slice()),
        }
    }
}

impl From<master::MasterStepThree> for MasterStepThree {
    #[inline]
    fn from(m: master::MasterStepThree) -> Self {
        Self {
            e_ab_masked: m.e_ab_masked.to_bytes(),
        }
    }
}

impl From<MasterStepThree> for master::MasterStepThree {
    #[inline]
    fn from(m: MasterStepThree) -> Self {
        Self {
            e_ab_masked: BigInt::from_bytes(m.e_ab_masked.as_slice()),
        }
    }
}

impl From<slave::SlaveStepOne> for SlaveStepOne {
    #[inline]
    fn from(m: slave::SlaveStepOne) -> Self {
        Self {
            n_a_mod_p: m.n_a_mod_p.to_bytes(),
            n_t_mod_p: m.n_t_mod_p.to_bytes(),
            e_a_masked: m.e_a_masked.to_bytes(),
            e_t_masked: m.e_t_masked.to_bytes(),
        }
    }
}

impl From<SlaveStepOne> for slave::SlaveStepOne {
    #[inline]
    fn from(m: SlaveStepOne) -> Self {
        Self {
            n_a_mod_p: BigInt::from_bytes(m.n_a_mod_p.as_slice()),
            n_t_mod_p: BigInt::from_bytes(m.n_t_mod_p.as_slice()),
            e_a_masked: BigInt::from_bytes(m.e_a_masked.as_slice()),
            e_t_masked: BigInt::from_bytes(m.e_t_masked.as_slice()),
        }
    }
}

impl From<slave::SlaveStepTwo> for SlaveStepTwo {
    #[inline]
    fn from(m: slave::SlaveStepTwo) -> Self {
        Self {
            n_b_mod_p: m.n_b_mod_p.to_bytes(),
            e_b_masked: m.e_b_masked.to_bytes(),
        }
    }
}

impl From<SlaveStepTwo> for slave::SlaveStepTwo {
    #[inline]
    fn from(m: SlaveStepTwo) -> Self {
        Self {
            n_b_mod_p: BigInt::from_bytes(m.n_b_mod_p.as_slice()),
            e_b_masked: BigInt::from_bytes(m.e_b_masked.as_slice()),
        }
    }
}

impl From<slave::SlaveStepThree> for SlaveStepThree {
    #[inline]
    fn from(m: slave::SlaveStepThree) -> Self {
        Self {
            e_pms_masked: m.e_pms_masked.to_bytes(),
        }
    }
}

impl From<SlaveStepThree> for slave::SlaveStepThree {
    #[inline]
    fn from(m: SlaveStepThree) -> Self {
        Self {
            e_pms_masked: BigInt::from_bytes(m.e_pms_masked.as_slice()),
        }
    }
}
