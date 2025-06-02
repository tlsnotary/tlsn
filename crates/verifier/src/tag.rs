//! TLS 1.2 record AES-GCM tag verification.

use mpz_core::bitvec::BitVec;
use mpz_memory_core::DecodeFutureTyped;
use tls_core::cipher::make_tls12_aad;
use tlsn_common::{ghash::ghash, tag::J0Proof, transcript::Record};

use crate::VerifierError;

pub(crate) fn verify_tags<'record>(
    proof: J0Proof,
    mut mac_key: DecodeFutureTyped<BitVec, [u8; 16]>,
    records: impl Iterator<Item = &'record Record>,
) -> Result<(), VerifierError> {
    let mac_key = mac_key
        .try_recv()
        .map_err(VerifierError::zk)?
        .expect("the key should be decoded");

    for (mut j0, rec) in proof.j0s.into_iter().zip(records) {
        let j0 = j0
            .try_recv()
            .map_err(VerifierError::zk)?
            .expect("j0 should be decoded");

        let aad = make_tls12_aad(rec.seq, rec.typ, rec.version, rec.ciphertext.len());

        let ghash_tag = ghash(aad.as_ref(), &rec.ciphertext, &mac_key);

        let aes_gcm_tag = match rec.tag.as_ref() {
            Some(tag) => tag,
            None => {
                // This will never happen, since we only call this method
                // on the received records for which the tags are known.
                return Err(VerifierError::internal(
                    "cannot verify a record with an unknown tag",
                ));
            }
        };

        if *aes_gcm_tag
            != ghash_tag
                .into_iter()
                .zip(j0.into_iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>()
        {
            return Err(VerifierError::mpc("tag verification failed"));
        }
    }

    Ok(())
}
