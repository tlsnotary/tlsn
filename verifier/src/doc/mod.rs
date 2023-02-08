//! Types associated with various stages of the notarization document
mod checks;
pub mod unchecked;
pub(crate) mod validated;
pub(crate) mod verified;

/// The maximum total size of all committed data in one document. Used to prevent DoS
/// during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of labels if the
/// commitment type is [crate::commitment::CommitmentType::labels_blake3])
const MAX_TOTAL_COMMITTED_DATA: u64 = 1000000000;
/// The maximum count of commitments in one document. Used to prevent DoS since searching for
/// overlapping commitments in the naive way which we implemented has quadratic cost.
const MAX_COMMITMENT_COUNT: u16 = 1000;

#[cfg(test)]
pub mod test {
    use crate::{
        commitment::{
            Commitment, CommitmentOpening, CommitmentType, Direction, LabelsBlake3Opening,
            SomeFutureVariantOpening, TranscriptRange,
        },
        doc::unchecked::UncheckedDoc,
        merkle::MerkleProof,
        pubkey::{KeyType, PubKey},
        signed::{Signed, SignedHandshake},
        tls_handshake::{
            EphemeralECPubkey, EphemeralECPubkeyType, HandshakeData, KEParamsSigAlg,
            ServerSignature, TLSHandshake,
        },
        HashCommitment, LabelSeed, TranscriptVerifier,
    };
    use ::blake3::Hasher;
    use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
    use rand::Rng;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    // Constructs an unchecked document with 2 commitments
    pub fn unchecked_doc(
        label_seed: LabelSeed,
        hash_commitments: [HashCommitment; 2],
        // 2 ranges for the first commitment and 2 ranges for the second commitment
        ranges: [[TranscriptRange; 2]; 2],
    ) -> UncheckedDoc {
        let mut rng = rand::thread_rng();

        // plaintext padded to a multiple of 16 bytes
        let plaintext = b"This important data will be notarized...........";

        // -------- After the webserver sends the Server Key Exchange message (during the TLS handshake),
        //          the tls-client module provides the following TLS data:

        /// end entity cert
        static EE: &[u8] = include_bytes!("../../src/testdata/tlsnotary.org/ee.der");
        // intermediate cert
        static INTER: &[u8] = include_bytes!("../../src/testdata/tlsnotary.org/inter.der");
        // certificate authority cert
        static CA: &[u8] = include_bytes!("../../src/testdata/tlsnotary.org/ca.der");
        let cert_chain = vec![CA.to_vec(), INTER.to_vec(), EE.to_vec()];
        // unix time when the cert chain was valid
        static TIME: u64 = 1671637529;

        // data taken from an actual network trace captured with `tcpdump host tlsnotary.org -w out.pcap`
        // (see testdata/key_exchange/README for details)

        let client_random =
            hex::decode("ac3808970faf996d38864e205c6b787a1d05f681654a5d2a3c87f7dd2f13332e")
                .unwrap();
        let server_random =
            hex::decode("8abf9a0c4b3b9694edac3d19e8eb7a637bfa8fe5644bd9f1444f574e47524401")
                .unwrap();
        let ephemeral_pubkey = hex::decode("04521e456448e6156026bb1392e0a689c051a84d67d353ab755fce68a2e9fba68d09393fa6485db84517e16d9855ce5ba3ec2293f2e511d1e315570531722e9788").unwrap();
        let sig = hex::decode("337aa65793562550f6de0a9c792b5f531a96bb78f65a2063f710bfb99e11c791e13d35c798b50eea1351c14efc526009c7836e888206cebde7135130a1fbc049d42e1d1ed05c10f0d108b9540f049ac24fe1076d391b9da3d4e60b5cb8f341bda993f6002873847be744c1955ff575b2d833694fb8a432898c5ac55752e2bddcee4c07371335e1a6581694df43c6eb0ce8da4cdd497c205607b573f9c5d17c951e0a71fbf967c4bff53fc37c597b2f5656478fefb780e8f37bd8409985dd980eda4f254c7dce76dc69e66ed27c0f2c93b53a6dfd7b27359e1589a30d483725e92305766c62d6cad2c0142d3a3c4a2272e6d81eda2886ef12028167f83b3c33ea").unwrap();

        let server_sig = ServerSignature::new(KEParamsSigAlg::RSA_PKCS1_2048_8192_SHA256, sig);

        let ephemeral_pubkey =
            EphemeralECPubkey::new(EphemeralECPubkeyType::P256, ephemeral_pubkey);

        // -------- Using the above data, the User computes [HandshakeData] and sends a commitment to
        //          the Notary

        let handshake_data =
            HandshakeData::new(cert_chain, server_sig, client_random, server_random);
        let handshake_commitment = blake3(&handshake_data.serialize().unwrap());

        // -------- The Notary generates garbled circuit's labels from a PRG seed (label_seed which
        //          was passed in).

        // ---------- After the notar. session is over and Notary revealed his label_seed: --------

        // -------- The User computes all her (salted) commitments

        let salt: [u8; 32] = rng.gen();

        // The User expands label_seed to obtain all labels, then hashes all the active labels (salted)
        // in the commitment's ranges (the result is `hash_commitments` which was passed in)

        let comm1 = Commitment::new(
            0,
            CommitmentType::labels_blake3,
            Direction::Sent,
            hash_commitments[0],
            ranges[0].to_vec(),
            0,
        );

        let comm2 = Commitment::new(
            1,
            CommitmentType::some_future_commitment_type,
            Direction::Received,
            hash_commitments[1],
            ranges[1].to_vec(),
            10,
        );

        // -------- The User creates a merkle tree of commitments and then a merkle proof of inclusion.
        //          Sends the merkle_root to the Notary

        // fill with 8 random leaves between index 0 and 10
        let random8: [HashCommitment; 8] = rng.gen();
        let leaves = [
            [hash_commitments[0]].to_vec(),
            random8.to_vec(),
            [hash_commitments[1]].to_vec(),
        ]
        .concat();
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().unwrap();

        // -------- the Notary uses his pubkey to compute a signature
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded = verifying_key.to_encoded_point(true);
        let pubkey_bytes = encoded.as_bytes();

        // (note that `ephemeral_pubkey` is known both to the User and the Notary)
        let signed_handshake = SignedHandshake::new(TIME, ephemeral_pubkey, handshake_commitment);
        let signed = Signed::new(signed_handshake.clone(), label_seed, merkle_root);

        let signature = signing_key.sign(&bincode::serialize(&signed).unwrap());
        let sig_der = signature.to_der();
        let signature = sig_der.as_bytes();

        // -------- the Notary reveals `label_seed` and also sends the `signature` and `time`.

        // -------- After that the User creates a doc for the Verifier:
        //          (The User creates `signed_handshake` just like the Notary did above)
        let tls_handshake = TLSHandshake::new(signed_handshake, handshake_data);

        // prepares openings and merkle proofs for those openings
        let opening1_bytes = bytes_in_ranges(plaintext, ranges[0].as_ref());
        let open1 = CommitmentOpening::LabelsBlake3(LabelsBlake3Opening::new(
            0,
            opening1_bytes,
            salt.to_vec(),
            label_seed,
        ));

        let opening2_bytes = bytes_in_ranges(plaintext, ranges[1].as_ref());
        let open2 = CommitmentOpening::SomeFutureVariant(SomeFutureVariantOpening::new(
            1,
            opening2_bytes,
            salt.to_vec(),
        ));

        let indices_to_prove = vec![0, 10];
        let proof = MerkleProof(merkle_tree.proof(&indices_to_prove));

        UncheckedDoc::new(
            1,
            tls_handshake,
            Some(signature.to_vec()),
            label_seed,
            merkle_root,
            2,
            proof,
            vec![comm1, comm2],
            vec![open1, open2],
        )
    }

    /// Returns a substring of the original `bytestring` containing only the bytes in `ranges`.
    /// This method is only called with validated `ranges` which do not exceed the size of the
    /// `bytestring`.
    fn bytes_in_ranges(bytestring: &[u8], ranges: &[TranscriptRange]) -> Vec<u8> {
        let mut substring: Vec<u8> = Vec::new();
        for r in ranges {
            substring.append(&mut bytestring[r.start() as usize..r.end() as usize].to_vec())
        }
        substring
    }
    /// Outputs blake3 digest
    fn blake3(data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}
