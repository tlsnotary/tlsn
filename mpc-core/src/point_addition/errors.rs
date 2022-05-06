/// Errors that may occur when using the point_addition module
#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error("Message was received out of order")]
    OutOfOrder,
}
