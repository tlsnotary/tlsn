pub mod master;
pub mod slave;

use curv::BigInt;
pub use master::SecretShareMasterCore;
pub use slave::SecretShareSlaveCore;

/// NIST P-256 Prime
pub const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

pub type SecretShare = BigInt;

#[derive(Debug)]
pub enum SecretShareMessage {
    M1(master::M1),
    M2(master::M2),
    M3(master::M3),
    S1(slave::S1),
    S2(slave::S2),
    S3(slave::S3),
}

impl From<master::M1> for SecretShareMessage {
    fn from(m: master::M1) -> Self {
        Self::M1(m)
    }
}

impl From<master::M2> for SecretShareMessage {
    fn from(m: master::M2) -> Self {
        Self::M2(m)
    }
}

impl From<master::M3> for SecretShareMessage {
    fn from(m: master::M3) -> Self {
        Self::M3(m)
    }
}

impl From<slave::S1> for SecretShareMessage {
    fn from(m: slave::S1) -> Self {
        Self::S1(m)
    }
}

impl From<slave::S2> for SecretShareMessage {
    fn from(m: slave::S2) -> Self {
        Self::S2(m)
    }
}

impl From<slave::S3> for SecretShareMessage {
    fn from(m: slave::S3) -> Self {
        Self::S3(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::{arithmetic::Converter, BigInt};
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand::thread_rng;

    #[test]
    fn test_secret_share() {
        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let master_secret = SecretKey::random(&mut rng);
        let master_point =
            (&server_pk * &master_secret.to_nonzero_scalar()).to_encoded_point(false);

        let slave_secret = SecretKey::random(&mut rng);
        let slave_point = (&server_pk * &slave_secret.to_nonzero_scalar()).to_encoded_point(false);

        let master = SecretShareMasterCore::new(&master_point);
        let slave = SecretShareSlaveCore::new(&slave_point);

        let (message, master) = master.next();
        let (message, slave) = slave.next(message);
        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);
        let (message, master) = master.next(message);
        let (message, slave) = slave.next(message);
        let master = master.next(message);

        let master_share = master.secret();
        let slave_share = slave.secret();

        let pms = ((&server_pk * &master_secret.to_nonzero_scalar())
            + (&server_pk * &slave_secret.to_nonzero_scalar()))
            .to_affine();
        let pms = BigInt::from_bytes(pms.to_encoded_point(false).x().unwrap());

        assert_eq!(
            pms,
            (master_share + slave_share) % BigInt::from_hex(P).unwrap()
        );
    }
}
