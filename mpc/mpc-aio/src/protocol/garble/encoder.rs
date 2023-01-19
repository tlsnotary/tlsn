use std::sync::Arc;

use futures::lock::{MappedMutexGuard, Mutex, MutexGuard};
use mpc_circuits::Input;
use mpc_core::garble::{ChaChaEncoder, Delta, FullInputLabels};
use rand_chacha::ChaCha20Rng;

/// Encodes wire labels using the ChaCha algorithm and a global offset (delta).
///
/// Stream ids can be used to partition labels sets.
///
/// `SharedChaChaEncoder` is `Clone` and can be shared across threads. This is useful
/// when you want to use a single seed to encode multiple circuits in parallel without
/// having to manage the rng state manually.
#[derive(Debug, Clone)]
pub struct SharedChaChaEncoder {
    encoder: Arc<Mutex<ChaChaEncoder>>,
}

impl SharedChaChaEncoder {
    /// Creates a new encoder with the provided seed
    ///
    /// * `seed` - 32-byte seed for ChaChaRng
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            encoder: Arc::new(Mutex::new(ChaChaEncoder::new(seed))),
        }
    }

    /// Returns encoder's rng seed
    pub async fn get_seed(&self) -> [u8; 32] {
        self.encoder.lock().await.get_seed()
    }

    /// Returns encoder's global offset
    pub async fn get_delta(&self) -> Delta {
        self.encoder.lock().await.get_delta()
    }

    /// Encodes input using the provided stream id
    ///
    /// * `stream_id` - Stream id, must be less than or equal to (u64::MAX >> 1)
    /// * `input` - Circuit input to encode
    pub async fn encode(&mut self, stream_id: u64, input: &Input) -> FullInputLabels {
        self.encoder.lock().await.encode(stream_id, input)
    }

    /// Returns a mutable reference to the encoder's rng
    ///
    /// * `stream_id` - Stream id, must be less than or equal to (u64::MAX >> 1)
    pub async fn get_stream(
        &mut self,
        stream_id: u64,
    ) -> MappedMutexGuard<'_, ChaChaEncoder, ChaCha20Rng> {
        MutexGuard::map(self.encoder.lock().await, |encoder| {
            encoder.get_stream(stream_id)
        })
    }
}

#[cfg(test)]
mod test {
    use mpc_circuits::{Circuit, WireGroup, ADDER_64};

    use super::*;

    #[tokio::test]
    async fn test_encoder() {
        let circ = Circuit::load_bytes(ADDER_64).unwrap();
        let mut enc = SharedChaChaEncoder::new([0u8; 32]);

        for input in circ.inputs() {
            enc.encode(input.index() as u64, input).await;
        }
    }
}
