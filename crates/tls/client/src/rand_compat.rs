//! Bridges a `rand_core` 0.10 RNG to the `rand_core` 0.6 interface required by
//! `p256` (`EphemeralSecret::random`, ...). Replaces the `rand06-compat` crate,
//! which only bridges `rand_core` 0.6 <-> 0.9.
//!
//! A single impl covers both an owned RNG and a `&mut` borrow, since
//! `rand_core` 0.10 blanket-implements `Rng` for `&mut R`.

/// Wraps a `rand_core` 0.10 RNG, exposing the `rand_core` 0.6 traits.
pub(crate) struct Compat<R>(pub(crate) R);

impl<R: rand::Rng> p256::elliptic_curve::rand_core::RngCore for Compat<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: rand::CryptoRng> p256::elliptic_curve::rand_core::CryptoRng for Compat<R> {}
