/// Encryption modes for the backend.
#[derive(Debug, Clone)]
pub enum EncryptMode {
    /// Encrypt payload with PSK
    EarlyData,
    /// Encrypt payload with Handshake keys
    Handshake,
    /// Encrypt payload with Application traffic keys
    Application,
}

/// Decryption modes for the backend.
#[derive(Debug, Clone)]
pub enum DecryptMode {
    /// Decrypt payload with Handshake keys
    Handshake,
    /// Decrypt payload with Application traffic keys
    Application,
}
