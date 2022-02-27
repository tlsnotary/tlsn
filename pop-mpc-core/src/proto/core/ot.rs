pub use crate::ot;
use crate::utils::parse_ristretto_key;
use std::convert::TryFrom;

include!(concat!(env!("OUT_DIR"), "/core.ot.rs"));

impl From<ot::BaseOtSenderSetup> for BaseOtSenderSetup {
    #[inline]
    fn from(s: ot::BaseOtSenderSetup) -> Self {
        Self {
            public_key: s.public_key.compress().as_bytes().to_vec(),
        }
    }
}

impl TryFrom<BaseOtSenderSetup> for ot::BaseOtSenderSetup {
    type Error = &'static str;

    #[inline]
    fn try_from(s: BaseOtSenderSetup) -> Result<Self, Self::Error> {
        let key = match parse_ristretto_key(s.public_key) {
            Ok(key) => key,
            Err(p) => return Err("Invalid key in BaseOtSenderSetup"),
        };
        Ok(Self { public_key: key })
    }
}

impl From<ot::BaseOtSenderPayload> for BaseOtSenderPayload {
    #[inline]
    fn from(p: ot::BaseOtSenderPayload) -> Self {
        let (low, high) = p
            .encrypted_values
            .into_iter()
            .map(|b| (super::Block::from(b[0]), super::Block::from(b[1])))
            .unzip();
        Self { low, high }
    }
}

impl From<BaseOtSenderPayload> for ot::BaseOtSenderPayload {
    #[inline]
    fn from(p: BaseOtSenderPayload) -> Self {
        Self {
            encrypted_values: p
                .low
                .into_iter()
                .zip(p.high.into_iter())
                .map(|(low, high)| [crate::Block::from(low), crate::Block::from(high)])
                .collect(),
        }
    }
}

impl From<ot::BaseOtReceiverSetup> for BaseOtReceiverSetup {
    #[inline]
    fn from(s: ot::BaseOtReceiverSetup) -> Self {
        Self {
            keys: s
                .keys
                .into_iter()
                .map(|k| super::RistrettoPoint::from(k))
                .collect(),
        }
    }
}

impl TryFrom<BaseOtReceiverSetup> for ot::BaseOtReceiverSetup {
    type Error = &'static str;

    #[inline]
    fn try_from(s: BaseOtReceiverSetup) -> Result<Self, Self::Error> {
        let mut keys: Vec<curve25519_dalek::ristretto::RistrettoPoint> =
            Vec::with_capacity(s.keys.len());
        for key in s.keys.into_iter() {
            let key = match parse_ristretto_key(key.point) {
                Ok(p) => p,
                Err(k) => return Err("Invalid key in BaseOtReceiverSetup"),
            };
            keys.push(key);
        }
        Ok(Self { keys })
    }
}

impl From<ot::OtReceiverSetup> for OtReceiverSetup {
    #[inline]
    fn from(s: ot::OtReceiverSetup) -> Self {
        Self {
            ncols: s.ncols as u32,
            table: s.table,
        }
    }
}

impl From<OtReceiverSetup> for ot::OtReceiverSetup {
    #[inline]
    fn from(s: OtReceiverSetup) -> Self {
        Self {
            ncols: s.ncols as usize,
            table: s.table,
        }
    }
}

impl From<ot::OtSenderPayload> for OtSenderPayload {
    #[inline]
    fn from(p: ot::OtSenderPayload) -> Self {
        let (low, high) = p
            .encrypted_values
            .into_iter()
            .map(|b| (super::Block::from(b[0]), super::Block::from(b[1])))
            .unzip();
        Self { low, high }
    }
}

impl From<OtSenderPayload> for ot::OtSenderPayload {
    #[inline]
    fn from(p: OtSenderPayload) -> Self {
        Self {
            encrypted_values: p
                .low
                .into_iter()
                .zip(p.high.into_iter())
                .map(|(low, high)| [crate::Block::from(low), crate::Block::from(high)])
                .collect(),
        }
    }
}
