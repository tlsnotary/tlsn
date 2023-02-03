use super::*;

use futures::{
    channel::oneshot::{channel, Sender},
    lock::Mutex,
};
use mpc_core::garble::{ChaChaEncoder, Encoder};
use std::sync::Arc;

use p256::{
    elliptic_curve::{AffineXCoordinate, Field, PrimeField},
    ProjectivePoint, Scalar,
};

pub fn create_mock_point_addition_pair(
    leader_encoder: Arc<Mutex<ChaChaEncoder>>,
    follower_encoder: Arc<Mutex<ChaChaEncoder>>,
) -> (MockP256PointAddition, MockP256PointAddition) {
    let buffer = Arc::new(Mutex::new(None));

    let leader = MockP256PointAddition {
        encoder: leader_encoder,
        buffer: buffer.clone(),
    };

    let follower = MockP256PointAddition {
        encoder: follower_encoder,
        buffer,
    };

    (leader, follower)
}

struct Buffer {
    full_share_a_labels: FullLabels,
    full_share_b_labels: FullLabels,
    point: ProjectivePoint,
    channel: Sender<XCoordinateLabels>,
}

#[derive(Clone)]
pub struct MockP256PointAddition {
    encoder: Arc<Mutex<ChaChaEncoder>>,
    buffer: Arc<Mutex<Option<Buffer>>>,
}

#[async_trait]
impl PointAddition for MockP256PointAddition {
    type Point = ProjectivePoint;
    type XCoordinate = XCoordinateLabels;

    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError> {
        let mut encoder = self.encoder.lock().await;
        let delta = encoder.get_delta();
        let full_share_a_labels =
            FullLabels::generate(&mut encoder.get_stream(0), 256, Some(delta));
        let full_share_b_labels =
            FullLabels::generate(&mut encoder.get_stream(0), 256, Some(delta));
        drop(encoder);

        let mut buffer = self.buffer.lock().await;
        // If buffer is already set, we compute the shares and send one of them over the channel.
        // Otherwise, we set the buffer and wait for the other party to send our share.
        if let Some(buffer) = buffer.take() {
            let shared_point = buffer.point + point;
            let x = shared_point.to_affine().x();

            let x = Scalar::from_repr(x).unwrap();
            let diff = Scalar::random(&mut rand::thread_rng());

            let x_a = x.sub(&diff);
            let x_b = diff;

            let mut x_a_bytes = x_a.to_bytes().to_vec();
            let mut x_b_bytes = x_b.to_bytes().to_vec();

            // Reverse to little-endian
            x_a_bytes.reverse();
            x_b_bytes.reverse();

            let our_labels = XCoordinateLabels {
                full_share_a_labels: full_share_a_labels.clone(),
                full_share_b_labels: full_share_b_labels.clone(),
                active_share_a_labels: buffer
                    .full_share_a_labels
                    .select(&x_a_bytes.clone().into())
                    .expect("Share labels should be valid"),
                active_share_b_labels: buffer
                    .full_share_b_labels
                    .select(&x_b_bytes.clone().into())
                    .expect("Share labels should be valid"),
            };

            let their_labels = XCoordinateLabels {
                full_share_a_labels: buffer.full_share_a_labels.clone(),
                full_share_b_labels: buffer.full_share_b_labels.clone(),
                active_share_a_labels: full_share_a_labels
                    .select(&x_a_bytes.into())
                    .expect("Share labels should be valid"),
                active_share_b_labels: full_share_b_labels
                    .select(&x_b_bytes.into())
                    .expect("Share labels should be valid"),
            };

            buffer.channel.send(their_labels).unwrap();

            return Ok(our_labels);
        } else {
            let (sender, receiver) = channel();
            *buffer = Some(Buffer {
                full_share_a_labels,
                full_share_b_labels,
                point,
                channel: sender,
            });
            drop(buffer);

            return Ok(receiver.await.unwrap());
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use p256::{elliptic_curve::generic_array, SecretKey};
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_mock_share_x_coordinate() {
        let leader_encoder = Arc::new(Mutex::new(ChaChaEncoder::new([0u8; 32])));
        let follower_encoder = Arc::new(Mutex::new(ChaChaEncoder::new([1u8; 32])));

        let (mut leader, mut follower) =
            create_mock_point_addition_pair(leader_encoder, follower_encoder);

        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0);

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key();

        let leader_secret = SecretKey::random(&mut rng);

        let follower_secret = SecretKey::random(&mut rng);

        let leader_point = &server_pk.to_projective() * &leader_secret.to_nonzero_scalar();
        let follower_point = &server_pk.to_projective() * &follower_secret.to_nonzero_scalar();

        let shared_point = &leader_point + &follower_point;

        let expected_shared_x = Scalar::from_repr(shared_point.to_affine().x()).unwrap();

        let (leader_share, follower_share) = futures::join!(
            async {
                leader
                    .compute_x_coordinate_share(leader_point)
                    .await
                    .unwrap()
            },
            async {
                follower
                    .compute_x_coordinate_share(follower_point)
                    .await
                    .unwrap()
            }
        );

        let XCoordinateLabels {
            full_share_a_labels: leader_full_share_a_labels,
            full_share_b_labels: leader_full_share_b_labels,
            active_share_a_labels: leader_active_share_a_labels,
            active_share_b_labels: leader_active_share_b_labels,
        } = leader_share;

        let XCoordinateLabels {
            full_share_a_labels: follower_full_share_a_labels,
            full_share_b_labels: follower_full_share_b_labels,
            active_share_a_labels: follower_active_share_a_labels,
            active_share_b_labels: follower_active_share_b_labels,
        } = follower_share;

        // Decode labels and convert to Scalar
        let leader_share_a = leader_active_share_a_labels
            .decode(follower_full_share_a_labels.get_decoding())
            .unwrap();
        let leader_share_a = leader_share_a
            .chunks_exact(8)
            .map(|bits| {
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u8) << i)
            })
            .rev()
            .collect::<Vec<u8>>();

        let leader_share_a =
            Scalar::from_repr(*generic_array::GenericArray::from_slice(&leader_share_a)).unwrap();

        // Decode labels and convert to Scalar
        let leader_share_b = leader_active_share_b_labels
            .decode(follower_full_share_b_labels.get_decoding())
            .unwrap();
        let leader_share_b = leader_share_b
            .chunks_exact(8)
            .map(|bits| {
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u8) << i)
            })
            .rev()
            .collect::<Vec<u8>>();

        let leader_share_b =
            Scalar::from_repr(*generic_array::GenericArray::from_slice(&leader_share_b)).unwrap();

        // Decode labels and convert to Scalar
        let follower_share_a = follower_active_share_a_labels
            .decode(leader_full_share_a_labels.get_decoding())
            .unwrap();
        let follower_share_a = follower_share_a
            .chunks_exact(8)
            .map(|bits| {
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u8) << i)
            })
            .rev()
            .collect::<Vec<u8>>();

        let follower_share_a =
            Scalar::from_repr(*generic_array::GenericArray::from_slice(&follower_share_a)).unwrap();

        // Decode labels and convert to Scalar
        let follower_share_b = follower_active_share_b_labels
            .decode(leader_full_share_b_labels.get_decoding())
            .unwrap();
        let follower_share_b = follower_share_b
            .chunks_exact(8)
            .map(|bits| {
                bits.iter()
                    .enumerate()
                    .fold(0, |acc, (i, v)| acc | (*v as u8) << i)
            })
            .rev()
            .collect::<Vec<u8>>();

        let follower_share_b =
            Scalar::from_repr(*generic_array::GenericArray::from_slice(&follower_share_b)).unwrap();

        let leader_shared_x = leader_share_a.add(&leader_share_b);
        let follower_shared_x = follower_share_a.add(&follower_share_b);

        assert_eq!(leader_shared_x, expected_shared_x);
        assert_eq!(follower_shared_x, expected_shared_x);
    }
}
