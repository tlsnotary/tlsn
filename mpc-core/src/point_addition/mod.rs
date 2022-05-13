//! This crate implements EC point addition in 2PC using the Paillier
//! cryptosystem. The two parties have their secret points A and B which they
//! want to add. At the end, the parties will have with their shares of the
//! resulting point's X coordinate. (Obtaining the shares of the Y coordinate
//! would also be possible using this approach, but it hasn't been
//! implemented here).

pub mod errors;
pub mod master;
pub mod slave;

pub use crate::point_addition::errors::PointAdditionError;
use curv::{arithmetic::Converter, BigInt};
pub use master::PointAdditionMaster;
pub use slave::PointAdditionSlave;

/// NIST P-256 Prime
pub const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

pub type SecretShare = BigInt;

#[derive(PartialEq, Debug)]
pub enum PointAdditionMessage {
    M1(master::M1),
    M2(master::M2),
    M3(master::M3),
    S1(slave::S1),
    S2(slave::S2),
    S3(slave::S3),
}

pub trait MasterCore {
    /// processes the next message of the protocol
    fn next(
        &mut self,
        message: Option<PointAdditionMessage>,
    ) -> Result<Option<PointAdditionMessage>, PointAdditionError>;

    fn is_complete(&self) -> bool;

    /// returns Master's share of the resulting X coordinate
    fn get_secret(self) -> Result<SecretShare, PointAdditionError>;
}

pub trait SlaveCore {
    /// processes the next message of the protocol
    fn next(
        &mut self,
        message: Option<PointAdditionMessage>,
    ) -> Result<Option<PointAdditionMessage>, PointAdditionError>;

    fn is_complete(&self) -> bool;

    /// returns Slave's share of the resulting X coordinate
    fn get_secret(self) -> Result<SecretShare, PointAdditionError>;
}

pub fn combine_shares(a: SecretShare, b: SecretShare) -> Vec<u8> {
    ((a + b) % BigInt::from_hex(P).unwrap()).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand::thread_rng;

    #[test]
    fn test_point_addition() {
        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let master_secret = SecretKey::random(&mut rng);
        let master_point =
            (&server_pk * &master_secret.to_nonzero_scalar()).to_encoded_point(false);

        let slave_secret = SecretKey::random(&mut rng);
        let slave_point = (&server_pk * &slave_secret.to_nonzero_scalar()).to_encoded_point(false);

        let mut master = PointAdditionMaster::new(&master_point);
        let mut slave = PointAdditionSlave::new(&slave_point);

        let mut master_message;
        let mut slave_message: Option<PointAdditionMessage> = None;
        loop {
            if !master.is_complete() {
                master_message = master.next(slave_message).unwrap();
            } else {
                master_message = None;
            }
            if !slave.is_complete() {
                slave_message = slave.next(master_message).unwrap();
            } else {
                slave_message = None;
            }
            if master.is_complete() && slave.is_complete() {
                break;
            }
        }

        let master_share = master.get_secret().unwrap();
        let slave_share = slave.get_secret().unwrap();

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
