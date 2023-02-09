use super::{PointAddition, PointAdditionError};
use async_trait::async_trait;
use p256::EncodedPoint;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use share_conversion_core::fields::{p256::P256, Field, UniformRand};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct MockConverter {
    sharing: Arc<Mutex<Option<P256>>>,
    rng: ChaCha12Rng,
}

impl MockConverter {
    pub fn new() -> Self {
        let rng = ChaCha12Rng::from_entropy();
        Self {
            sharing: Arc::new(Mutex::new(None)),
            rng,
        }
    }

    pub fn convert(&mut self, [x, y]: [P256; 2]) -> P256 {}

    fn a_to_m(&mut self, x: P256, y: P256) -> (P256, P256) {
        let sum = x + y;
        let a = P256::rand(&mut self.rng);
        let b = sum * a.inverse();
        (a, b)
    }

    fn m_to_a(&mut self, a: P256, b: P256) -> (P256, P256) {
        let product = a * b;
        let x = P256::rand(&mut self.rng);
        let y = product + -x;
        (x, y)
    }
}

#[async_trait]
impl PointAddition for MockConverter {
    type Point = EncodedPoint;
    type XCoordinate = P256;

    async fn compute_x_coordinate_share(
        &mut self,
        point: Self::Point,
    ) -> Result<Self::XCoordinate, PointAdditionError> {
        {
            let sharing = *self.sharing.lock().unwrap();
            if let Some(sharing) = sharing {
                return Ok(sharing);
            }
        }

        let mut rng = ChaCha12Rng::from_entropy();
        let point = point.to_bytes();
        let sharing = P256::rand(&mut rng);
        P256::new(point.into());

        todo!()
    }
}
