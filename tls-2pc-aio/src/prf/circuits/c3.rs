use mpc_aio::protocol::garble::{Execute, GCError};
use rand::{thread_rng, Rng};
use tls_2pc_core::{SessionKeyShares, CIRCUIT_3};

/// Executes c3 as PRFLeader
///
/// Returns session key shares
pub async fn leader_c3<T: Execute + Send>(
    exec: &mut T,
    p1_inner_hash: [u8; 32],
    p2_inner_hash: [u8; 32],
) -> Result<SessionKeyShares, GCError> {
    let circ = CIRCUIT_3.clone();

    let input_p1_inner_hash = circ
        .input(5)?
        .to_value(p1_inner_hash.iter().rev().copied().collect::<Vec<u8>>())?;

    let input_p2_inner_hash = circ
        .input(6)?
        .to_value(p2_inner_hash.iter().rev().copied().collect::<Vec<u8>>())?;

    let cwk_mask: Vec<u8> = thread_rng().gen::<[u8; 16]>().to_vec();
    let input_cwk_mask = circ.input(7)?.to_value(cwk_mask.clone())?;

    let swk_mask: Vec<u8> = thread_rng().gen::<[u8; 16]>().to_vec();
    let input_swk_mask = circ.input(8)?.to_value(swk_mask.clone())?;

    let civ_mask: Vec<u8> = thread_rng().gen::<[u8; 4]>().to_vec();
    let input_civ_mask = circ.input(9)?.to_value(civ_mask.clone())?;

    let siv_mask: Vec<u8> = thread_rng().gen::<[u8; 4]>().to_vec();
    let input_siv_mask = circ.input(10)?.to_value(siv_mask.clone())?;

    let inputs = vec![
        input_p1_inner_hash,
        input_p2_inner_hash,
        input_cwk_mask,
        input_swk_mask,
        input_civ_mask,
        input_siv_mask,
    ];

    let out = exec.execute(circ, &inputs).await?.decode()?;

    // todo make this less gross
    let cwk_masked = if let mpc_circuits::Value::Bytes(v) =
        out.get(0).expect("Circuit 3 should have output 1").value()
    {
        v
    } else {
        panic!("Circuit 3 output 0 should be 16 bytes")
    };

    let swk_masked = if let mpc_circuits::Value::Bytes(v) =
        out.get(1).expect("Circuit 3 should have output 0").value()
    {
        v
    } else {
        panic!("Circuit 3 output 1 should be 16 bytes")
    };

    let civ_masked = if let mpc_circuits::Value::Bytes(v) =
        out.get(2).expect("Circuit 3 should have output 2").value()
    {
        v
    } else {
        panic!("Circuit 3 output 2 should be 4 bytes")
    };

    let siv_masked = if let mpc_circuits::Value::Bytes(v) =
        out.get(3).expect("Circuit 3 should have output 2").value()
    {
        v
    } else {
        panic!("Circuit 3 output 3 should be 4 bytes")
    };

    // Only the leader removes their key masks
    let cwk = cwk_masked
        .iter()
        .zip(cwk_mask.iter())
        .map(|(a, b)| a ^ b)
        .rev()
        .collect::<Vec<u8>>();
    let swk = swk_masked
        .iter()
        .zip(swk_mask.iter())
        .map(|(a, b)| a ^ b)
        .rev()
        .collect::<Vec<u8>>();
    let civ = civ_masked
        .iter()
        .zip(civ_mask.iter())
        .map(|(a, b)| a ^ b)
        .rev()
        .collect::<Vec<u8>>();
    let siv = siv_masked
        .iter()
        .zip(siv_mask.iter())
        .map(|(a, b)| a ^ b)
        .rev()
        .collect::<Vec<u8>>();

    // The leader's key shares are k ⊕ follower_mask
    let cwk: [u8; 16] = cwk.try_into().expect("cwk should be 16 bytes");
    let swk: [u8; 16] = swk.try_into().expect("swk should be 16 bytes");
    let civ: [u8; 4] = civ.try_into().expect("civ should be 4 bytes");
    let siv: [u8; 4] = siv.try_into().expect("siv should be 4 bytes");

    Ok(SessionKeyShares::new(cwk, swk, civ, siv))
}

/// Executes c3 as PRFFollower
///
/// Returns outer_hash_state
pub async fn follower_c3<T: Execute + Send>(
    exec: &mut T,
    outer_hash_state: [u32; 8],
) -> Result<SessionKeyShares, GCError> {
    let circ = CIRCUIT_3.clone();

    let input_outer_hash_state = circ.input(0)?.to_value(
        outer_hash_state
            .into_iter()
            .rev()
            .map(|v| v.to_le_bytes())
            .flatten()
            .collect::<Vec<u8>>(),
    )?;

    let mut cwk_mask: Vec<u8> = thread_rng().gen::<[u8; 16]>().to_vec();
    let input_cwk_mask = circ.input(1)?.to_value(cwk_mask.clone())?;

    let mut swk_mask: Vec<u8> = thread_rng().gen::<[u8; 16]>().to_vec();
    let input_swk_mask = circ.input(2)?.to_value(swk_mask.clone())?;

    let mut civ_mask: Vec<u8> = thread_rng().gen::<[u8; 4]>().to_vec();
    let input_civ_mask = circ.input(3)?.to_value(civ_mask.clone())?;

    let mut siv_mask: Vec<u8> = thread_rng().gen::<[u8; 4]>().to_vec();
    let input_siv_mask = circ.input(4)?.to_value(siv_mask.clone())?;

    let inputs = vec![
        input_outer_hash_state,
        input_cwk_mask,
        input_swk_mask,
        input_civ_mask,
        input_siv_mask,
    ];

    let _ = exec.execute(circ, &inputs).await?.decode()?;

    cwk_mask.reverse();
    swk_mask.reverse();
    civ_mask.reverse();
    siv_mask.reverse();

    // The followers's key shares are just their masks
    let cwk: [u8; 16] = cwk_mask.try_into().expect("cwk should be 16 bytes");
    let swk: [u8; 16] = swk_mask.try_into().expect("swk should be 16 bytes");
    let civ: [u8; 4] = civ_mask.try_into().expect("civ should be 4 bytes");
    let siv: [u8; 4] = siv_mask.try_into().expect("siv should be 4 bytes");

    Ok(SessionKeyShares::new(cwk, swk, civ, siv))
}
