use futures::{AsyncReadExt, AsyncWriteExt};
use web_time::{SystemTime, UNIX_EPOCH};

use crate::IoProvider;

crate::test!("rtt", prover, verifier);

// Expected one-way delay in microseconds (TEST_PROTO_DELAY = 10ms)
const EXPECTED_DELAY_US: u64 = 10_000;
// Tolerance as a fraction (20% to account for TCP/async overhead)
const TOLERANCE: f64 = 0.20;

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

fn within_tolerance(actual: u64, expected: u64, tolerance: f64) -> bool {
    let min = (expected as f64 * (1.0 - tolerance)) as u64;
    let max = (expected as f64 * (1.0 + tolerance)) as u64;
    actual >= min && actual <= max
}

async fn prover(provider: &IoProvider) {
    let mut io = provider.provide_proto_io().await.unwrap();

    // Buffer for: prover_send(8) + verifier_recv(8) + verifier_send(8) = 24 bytes
    let mut buf = [0u8; 24];

    let t1_prover_send = now_micros();

    // Send T1 (prover send time)
    io.write_all(&t1_prover_send.to_le_bytes()).await.unwrap();
    io.flush().await.unwrap();

    // Receive: T1, T2 (verifier recv), T3 (verifier send)
    io.read_exact(&mut buf).await.unwrap();
    let t4_prover_recv = now_micros();

    let t1_returned = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let t2_verifier_recv = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let t3_verifier_send = u64::from_le_bytes(buf[16..24].try_into().unwrap());

    let p_to_v = t2_verifier_recv.saturating_sub(t1_returned);
    let v_to_p = t4_prover_recv.saturating_sub(t3_verifier_send);

    // Validate delays are within tolerance
    let p_to_v_ok = within_tolerance(p_to_v, EXPECTED_DELAY_US, TOLERANCE);
    let v_to_p_ok = within_tolerance(v_to_p, EXPECTED_DELAY_US, TOLERANCE);

    assert!(
        p_to_v_ok,
        "P->V delay out of range: {} us (expected {} +/- {}%)",
        p_to_v, EXPECTED_DELAY_US, (TOLERANCE * 100.0) as u32
    );

    assert!(
        v_to_p_ok,
        "V->P delay out of range: {} us (expected {} +/- {}%)",
        v_to_p, EXPECTED_DELAY_US, (TOLERANCE * 100.0) as u32
    );
}

async fn verifier(provider: &IoProvider) {
    let mut io = provider.provide_proto_io().await.unwrap();

    let mut buf = [0u8; 8];
    let mut response = [0u8; 24];

    // Receive T1 (prover send time)
    io.read_exact(&mut buf).await.unwrap();
    let t2_verifier_recv = now_micros();

    let t1_prover_send = u64::from_le_bytes(buf);

    // Prepare response: T1, T2, T3
    let t3_verifier_send = now_micros();
    response[0..8].copy_from_slice(&t1_prover_send.to_le_bytes());
    response[8..16].copy_from_slice(&t2_verifier_recv.to_le_bytes());
    response[16..24].copy_from_slice(&t3_verifier_send.to_le_bytes());

    io.write_all(&response).await.unwrap();
    io.flush().await.unwrap();
}
