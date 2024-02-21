//! TLSNotary protocol config and config utilities.

use crate::Role;

/// Default for the maximum number of bytes that can be sent (4Kb).
pub const DEFAULT_MAX_SENT_LIMIT: usize = 1 << 12;
/// Default for the maximum number of bytes that can be received (16Kb).
pub const DEFAULT_MAX_RECV_LIMIT: usize = 1 << 14;

// Determined experimentally, will be subject to change if underlying protocols are modified.
const KE_OTS: usize = 3360;
// Secret-sharing the GHASH blocks.
const GHASH_OTS: usize = 65664 * 2;
// Extra cushion room, eg. for sharing J0 blocks.
const EXTRA_OTS: usize = 16384;
const OTS_PER_BYTE_SENT: usize = 8;
// Without deferred decryption we use 16, with it we use 8.
const OTS_PER_BYTE_RECV: usize = 16;

/// Returns an estimate of the number of OTs that will be sent.
pub fn ot_send_estimate(role: Role, max_sent_data: usize, max_recv_data: usize) -> usize {
    match role {
        Role::Prover => KE_OTS + GHASH_OTS + EXTRA_OTS,
        Role::Verifier => {
            KE_OTS
                + EXTRA_OTS
                + (max_sent_data * OTS_PER_BYTE_SENT)
                + (max_recv_data * OTS_PER_BYTE_RECV)
        }
    }
}

/// Returns an estimate of the number of OTs that will be received.
pub fn ot_recv_estimate(role: Role, max_sent_data: usize, max_recv_data: usize) -> usize {
    match role {
        Role::Prover => {
            KE_OTS
                + EXTRA_OTS
                + (max_sent_data * OTS_PER_BYTE_SENT)
                + (max_recv_data * OTS_PER_BYTE_RECV)
        }
        Role::Verifier => KE_OTS + GHASH_OTS + EXTRA_OTS,
    }
}
