/// Errors that may occur when using ghash module
#[derive(Debug)]
pub enum GhashError {
    /// message received out of order
    OutOfORder,
    // flat vector's length is not a multiple of 128
    FlatWrongLength,
    // trying to set more blocks than the allowed maximum of 1026
    MaxBlocksExceeded,
}
