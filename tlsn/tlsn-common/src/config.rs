//! TLSNotary protocol config and config utilities.

use crate::Role;

/// Default for the maximum number of bytes that can be sent (4Kb).
pub const DEFAULT_MAX_SENT_LIMIT: usize = 1 << 12;
/// Default for the maximum number of bytes that can be received (16Kb).
pub const DEFAULT_MAX_RECV_LIMIT: usize = 1 << 14;

// Determined experimentally, will be subject to change if underlying protocols are modified.
const HANDSHAKE_OTS: usize = 3360;
// Extra cushion room, eg. for sharing J0 blocks.
const EXTRA_OTS: usize = 16384;
const CONST_OTS: usize = HANDSHAKE_OTS + EXTRA_OTS;

/// Returns an estimate of the number of OTs that will be sent.
pub fn ot_send_estimate(role: Role, max_sent_data: usize, max_recv_data: usize) -> usize {
    match role {
        Role::Prover => CONST_OTS,
        Role::Verifier => CONST_OTS + ((max_sent_data + max_recv_data) * 8),
    }
}

/// Returns an estimate of the number of OTs that will be received.
pub fn ot_recv_estimate(role: Role, max_sent_data: usize, max_recv_data: usize) -> usize {
    match role {
        Role::Prover => CONST_OTS + ((max_sent_data + max_recv_data) * 8),
        Role::Verifier => CONST_OTS,
    }
}
