use mpc_aio::protocol::{
    garble::{Execute, GCError},
    point_addition::P256SecretShare,
};
use rand::{thread_rng, Rng};
use tls_2pc_core::CIRCUIT_1;

/// Executes c1 as PRFLeader
///
/// Returns inner_hash_state
pub async fn leader_c1<T: Execute + Send>(
    exec: &mut T,
    secret_share: P256SecretShare,
) -> Result<[u32; 8], GCError> {
    let circ = CIRCUIT_1.clone();

    let input_pms_share = circ
        .input(0)
        .expect("Circuit 1 should have input 0")
        .to_value(
            secret_share
                .as_bytes()
                .iter()
                // convert to little-endian
                .rev()
                .copied()
                .collect::<Vec<u8>>(),
        )
        .expect("P256SecretShare should always be 32 bytes");

    let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
    let input_mask = circ
        .input(2)
        .expect("Circuit 1 should have input 2")
        .to_value(mask.clone())
        .expect("Mask should always be 32 bytes");

    let inputs = vec![input_pms_share, input_mask];
    let out = exec
        .execute(circ, &inputs)
        .await?
        .decode()
        .map_err(|e| GCError::from(e))?;

    // todo make this less gross
    let masked_inner_hash_state = if let mpc_circuits::Value::Bytes(v) =
        out.get(0).expect("Circuit 1 should have output 0").value()
    {
        v
    } else {
        panic!("Circuit 1 output 0 should be 32 bytes")
    };

    // remove XOR mask and convert to big-endian
    let inner_hash_state = masked_inner_hash_state
        .iter()
        .zip(mask.iter())
        .map(|(v, m)| v ^ m)
        .collect::<Vec<u8>>();

    let inner_hash_state: [u32; 8] = inner_hash_state
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes([chunk[3], chunk[2], chunk[1], chunk[0]]))
        .rev()
        .collect::<Vec<u32>>()
        .try_into()
        .expect("Circuit 1 output 0 should be 32 bytes");

    Ok(inner_hash_state)
}

/// Executes c1 as PRFFollower
///
/// Returns outer_hash_state
pub async fn follower_c1<T: Execute + Send>(
    exec: &mut T,
    secret_share: P256SecretShare,
) -> Result<[u32; 8], GCError> {
    let circ = CIRCUIT_1.clone();

    let input_pms_share = circ
        .input(1)
        .expect("Circuit 1 should have input 1")
        .to_value(
            secret_share
                .as_bytes()
                .iter()
                // convert to little-endian
                .rev()
                .copied()
                .collect::<Vec<u8>>(),
        )
        .expect("P256SecretShare should always be 32 bytes");

    let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
    let input_mask = circ
        .input(3)
        .expect("Circuit 1 should have input 3")
        .to_value(mask.clone())
        .expect("Mask should always be 32 bytes");

    let inputs = vec![input_pms_share, input_mask];
    let out = exec
        .execute(circ, &inputs)
        .await?
        .decode()
        .map_err(|e| GCError::from(e))?;

    // todo make this less gross
    let masked_outer_hash_state = if let mpc_circuits::Value::Bytes(v) =
        out.get(1).expect("Circuit 1 should have output 1").value()
    {
        v
    } else {
        panic!("Circuit 1 output 1 should be 32 bytes")
    };

    // remove XOR mask and convert to big-endian
    let outer_hash_state = masked_outer_hash_state
        .iter()
        .zip(mask.iter())
        .map(|(v, m)| v ^ m)
        .collect::<Vec<u8>>();

    let outer_hash_state: [u32; 8] = outer_hash_state
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes([chunk[3], chunk[2], chunk[1], chunk[0]]))
        .rev()
        .collect::<Vec<u32>>()
        .try_into()
        .expect("Circuit 1 output 1 should be 32 bytes");

    Ok(outer_hash_state)
}

#[cfg(test)]
mod tests {
    use mpc_aio::protocol::garble::exec::dual::mock_dualex_pair;
    use tls_2pc_core::prf::sha::partial_sha256_digest;

    use super::*;

    #[ignore = "expensive"]
    #[tokio::test]
    async fn test_c1() {
        let (mut gc_leader, mut gc_follower) = mock_dualex_pair();
        let leader_share = P256SecretShare::new([
            95, 183, 78, 37, 133, 230, 30, 137, 239, 195, 160, 166, 154, 80, 143, 115, 38, 92, 34,
            169, 61, 96, 130, 40, 42, 129, 231, 68, 109, 244, 150, 193,
        ]);
        let follower_share = P256SecretShare::new([
            141, 150, 106, 174, 105, 9, 169, 73, 234, 17, 111, 54, 214, 28, 160, 159, 148, 130,
            223, 55, 134, 50, 172, 164, 63, 158, 46, 149, 197, 226, 90, 29,
        ]);
        let pms = leader_share + follower_share;
        let mut pms_zeropadded = [0u8; 64];
        pms_zeropadded[..32].copy_from_slice(&pms);
        let pms_ipad = pms_zeropadded.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>();
        let pms_opad = pms_zeropadded.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>();
        let expected_inner_hash_state = partial_sha256_digest(&pms_ipad);
        let expected_outer_hash_state = partial_sha256_digest(&pms_opad);

        let (task_leader, task_follower) = tokio::join!(
            tokio::spawn(async move { leader_c1(&mut gc_leader, leader_share).await.unwrap() }),
            tokio::spawn(
                async move { follower_c1(&mut gc_follower, follower_share).await.unwrap() }
            )
        );

        let inner_hash_state = task_leader.unwrap();
        let outer_hash_state = task_follower.unwrap();

        assert_eq!(inner_hash_state, expected_inner_hash_state);
        assert_eq!(outer_hash_state, expected_outer_hash_state);
    }
}
