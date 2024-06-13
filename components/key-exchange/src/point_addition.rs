//! This module implements a secure two-party computation protocol for adding two private EC points
//! and secret-sharing the resulting x coordinate (the shares are field elements of the field
//! underlying the elliptic curve).
//! This protocol has semi-honest security.
//!
//! The protocol is described in <https://docs.tlsnotary.org/protocol/notarization/key_exchange.html>

use mpz_common::Context;
use mpz_fields::{p256::P256, Field};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use p256::EncodedPoint;

use crate::{config::Role, error::ErrorKind, KeyExchangeError};

/// Derives the x-coordinate share of an elliptic curve point.
pub(crate) async fn derive_x_coord_share<Ctx, C>(
    role: Role,
    ctx: &mut Ctx,
    converter: &mut C,
    share: EncodedPoint,
) -> Result<P256, KeyExchangeError>
where
    Ctx: Context,
    C: AdditiveToMultiplicative<Ctx, P256> + MultiplicativeToAdditive<Ctx, P256>,
{
    let [x, y] = decompose_point(share)?;

    // Follower negates their share coordinates.
    let inputs = match role {
        Role::Leader => vec![y, x],
        Role::Follower => vec![-y, -x],
    };

    let [a, b] = converter
        .to_multiplicative(ctx, inputs)
        .await?
        .try_into()
        .expect("output is same length as input");

    let c = a * b.inverse();
    let c = c * c;

    let d = converter.to_additive(ctx, vec![c]).await?[0];

    let x_r = d + -x;

    Ok(x_r)
}

/// Decomposes the x and y coordinates of a SEC1 encoded point.
fn decompose_point(point: EncodedPoint) -> Result<[P256; 2], KeyExchangeError> {
    // Coordinates are stored as big-endian bytes.
    let mut x: [u8; 32] = (*point.x().ok_or(KeyExchangeError::new(
        ErrorKind::Key,
        "key share is an identity point",
    ))?)
    .into();
    let mut y: [u8; 32] = (*point.y().ok_or(KeyExchangeError::new(
        ErrorKind::Key,
        "key share is an identity point or compressed",
    ))?)
    .into();

    // Reverse to little endian.
    x.reverse();
    y.reverse();

    let x = P256::try_from(x).unwrap();
    let y = P256::try_from(y).unwrap();

    Ok([x, y])
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_common::executor::test_st_executor;
    use mpz_fields::{p256::P256, Field};
    use mpz_share_conversion::ideal::ideal_share_converter;
    use p256::{
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        EncodedPoint, NonZeroScalar, ProjectivePoint, PublicKey,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[tokio::test]
    async fn test_point_addition() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let mut rng = ChaCha12Rng::from_seed([0u8; 32]);

        let p1: [u8; 32] = rng.gen();
        let p2: [u8; 32] = rng.gen();

        let p1 = curve_point_from_be_bytes(p1);
        let p2 = curve_point_from_be_bytes(p2);

        let p = add_curve_points(&p1, &p2);

        let (mut c_a, mut c_b) = ideal_share_converter();

        let (a, b) = tokio::try_join!(
            derive_x_coord_share(Role::Leader, &mut ctx_a, &mut c_a, p1),
            derive_x_coord_share(Role::Follower, &mut ctx_b, &mut c_b, p2)
        )
        .unwrap();

        let [expected_x, _] = decompose_point(p).unwrap();

        assert_eq!(expected_x, a + b);
    }

    #[test]
    fn test_decompose_point() {
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);

        let p_expected: [u8; 32] = rng.gen();
        let p_expected = curve_point_from_be_bytes(p_expected);

        let p256: [P256; 2] = decompose_point(p_expected).unwrap();

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
