use mpc_aio::protocol::garble::{Execute, GCError};
use rand::{thread_rng, Rng};
use tls_2pc_core::CIRCUIT_2;

/// Executes c2 as PRFLeader
///
/// Returns inner_hash_state
pub async fn leader_c2<T: Execute + Send>(
    exec: &mut T,
    p1_inner_hash: [u8; 32],
) -> Result<[u32; 8], GCError> {
    let circ = CIRCUIT_2.clone();

    // convert to little-endian
    let input_inner_hash = circ
        .input(1)?
        .to_value(p1_inner_hash.iter().rev().copied().collect::<Vec<u8>>())?;

    let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
    let input_mask = circ.input(3)?.to_value(mask.clone())?;

    let inputs = vec![input_inner_hash, input_mask];
    let out = exec.execute(circ, &inputs).await?.decode()?;

    // todo make this less gross
    let masked_inner_hash_state = if let mpc_circuits::Value::Bytes(v) =
        out.get(0).expect("Circuit 2 should have output 0").value()
    {
        v
    } else {
        panic!("Circuit 2 output 0 should be 32 bytes")
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
        .expect("Circuit 2 output 0 should be 32 bytes");

    Ok(inner_hash_state)
}

/// Executes c2 as PRFFollower
///
/// Returns outer_hash_state
pub async fn follower_c2<T: Execute + Send>(
    exec: &mut T,
    outer_hash_state: [u32; 8],
    p2: [u8; 32],
) -> Result<[u32; 8], GCError> {
    let circ = CIRCUIT_2.clone();

    // convert to little-endian
    let input_outer_hash_state = circ.input(0)?.to_value(
        outer_hash_state
            .into_iter()
            .rev()
            .map(|v| v.to_le_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    )?;

    let input_p2 = circ
        .input(2)?
        .to_value(p2[..16].iter().rev().copied().collect::<Vec<u8>>())?;

    let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
    let input_mask = circ.input(4)?.to_value(mask.clone())?;

    let inputs = vec![input_outer_hash_state, input_p2, input_mask];
    let out = exec.execute(circ, &inputs).await?.decode()?;

    // todo make this less gross
    let masked_outer_hash_state = if let mpc_circuits::Value::Bytes(v) =
        out.get(1).expect("Circuit 2 should have output 1").value()
    {
        v
    } else {
        panic!("Circuit 2 output 1 should be 32 bytes")
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
        .expect("Circuit 2 output 1 should be 32 bytes");

    Ok(outer_hash_state)
}
