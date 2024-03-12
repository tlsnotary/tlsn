//! A secure two-party computation (2PC) library for converting additive shares of an elliptic
//! curve (EC) point into additive shares of said point's x-coordinate. The additive shares of the
//! x-coordinate are finite field elements.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use mpz_fields::Field;
use mpz_share_conversion::ShareConversionError;

mod conversion;

/// A mock implementation of the [PointAddition] trait
#[cfg(feature = "mock")]
pub mod mock;

pub use conversion::{MpcPointAddition, Role};
pub use mpz_fields::p256::P256;

/// The error type for [PointAddition]
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error(transparent)]
    ShareConversion(#[from] ShareConversionError),
    #[error("Unable to get coordinates from elliptic curve point")]
    Coordinates,
}

/// A trait for secret-sharing the sum of two elliptic curve points as a sum of field elements
///
/// This trait is for securely secret-sharing the addition of two elliptic curve points.
/// Let `P + Q = O = (x, y)`. Each party receives additive shares of the x-coordinate.
#[async_trait]
pub trait PointAddition {
    /// The elliptic curve point type
    type Point;
    /// The x-coordinate type for the finite field underlying the EC
    type XCoordinate: Field;

    /// Adds two elliptic curve points in 2PC, returning respective secret shares
    /// of the resulting x-coordinate to both parties.
    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError>;
}

#[cfg(test)]
mod tests {
    use crate::{conversion::point_to_p256, mock::mock_point_converter_pair, PointAddition};
    use mpz_core::Block;
    use mpz_share_conversion_core::{fields::p256::P256, Field};
    use p256::{
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        EncodedPoint, NonZeroScalar, ProjectivePoint, PublicKey,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[tokio::test]
    async fn test_point_conversion() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);

        let p1: [u8; 32] = rng.gen();
        let p2: [u8; 32] = rng.gen();

        let p1 = curve_point_from_be_bytes(p1);
        let p2 = curve_point_from_be_bytes(p2);

        let p = add_curve_points(&p1, &p2);

        let (mut c1, mut c2) = mock_point_converter_pair("test");

        let c1_fut = c1.compute_x_coordinate_share(p1);
        let c2_fut = c2.compute_x_coordinate_share(p2);

        let (c1_output, c2_output) = tokio::join!(c1_fut, c2_fut);
        let (c1_output, c2_output) = (c1_output.unwrap(), c2_output.unwrap());

        assert_eq!(point_to_p256(p).unwrap()[0], c1_output + c2_output);
    }

    #[test]
    fn test_point_to_p256() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);

        let p_expected: [u8; 32] = rng.gen();
        let p_expected = curve_point_from_be_bytes(p_expected);

        let p256: [P256; 2] = point_to_p256(p_expected).unwrap();

        let x: [u8; 32] = p256[0].to_be_bytes().try_into().unwrap();
        let y: [u8; 32] = p256[1].to_be_bytes().try_into().unwrap();

        let p = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);

        assert_eq!(p_expected, p);
    }

    fn curve_point_from_be_bytes(bytes: [u8; 32]) -> EncodedPoint {
        let scalar = NonZeroScalar::from_repr(bytes.into()).unwrap();
        let pk = PublicKey::from_secret_scalar(&scalar);
        pk.to_encoded_point(false)
    }

    fn add_curve_points(p1: &EncodedPoint, p2: &EncodedPoint) -> EncodedPoint {
        let p1 = ProjectivePoint::from_encoded_point(p1).unwrap();
        let p2 = ProjectivePoint::from_encoded_point(p2).unwrap();
        let p = p1 + p2;
        p.to_encoded_point(false)
    }
}
