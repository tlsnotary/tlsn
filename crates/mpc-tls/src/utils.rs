use crate::MpcTlsError;

/// Split an opaque message into its constituent parts.
///
/// Returns the explicit nonce, ciphertext, and tag, respectively.
pub(crate) fn opaque_into_parts(
    mut msg: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), MpcTlsError> {
    let tag = msg.split_off(msg.len() - 16);
    let ciphertext = msg.split_off(8);
    let explicit_nonce = msg;

    if explicit_nonce.len() != 8 {
        return Err(MpcTlsError::other("explicit nonce length is not 8"));
    }

    Ok((explicit_nonce, ciphertext, tag))
}
