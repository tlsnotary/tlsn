pub mod master;
pub mod slave;

use curv::BigInt;
pub use master::SecretShareMaster;
pub use slave::SecretShareSlave;

/// NIST P-256 Prime
const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

pub type SecretShare = BigInt;

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

        let master = SecretShareMaster::new(master_point);
        let slave = SecretShareSlave::new(slave_point);

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
