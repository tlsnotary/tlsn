mod common;
pub mod follower;
pub mod leader;
mod utils;

/// YBits are Master's bits of Y in big-endian. Based on these bits
/// Master will send MXTable via OT.
/// The convention for the returned Y bits:
/// A) powers are in an ascending order: first powers[1], then powers[2] etc.
/// B) bits of each power are in big-endian.
type YBits = Vec<bool>;

/// MXTableFull is masked XTable which Slave has at the beginning of OT.
/// MXTableFull must not be revealed to Master.
type MXTableFull = Vec<[u128; 2]>;

/// MXTable is a masked x table which Master will end up having after OT.
type MXTable = Vec<u128>;

/// Errors that may occur when using ghash module
#[derive(Debug, thiserror::Error)]
pub enum GhashError {
    #[error("Message was received out of order")]
    OutOfOrder,
    #[error("The other party sent data of wrong size")]
    DataLengthWrong,
    #[error("Tried to pass unsupported block count")]
    BlockCountWrong,
    #[error("Tried to finalize before the protocol was complete")]
    FinalizeCalledTooEarly,
    #[error("There is no final share available")]
    NoFinalShare,
    #[error("Final state is reached")]
    FinalState,
}
