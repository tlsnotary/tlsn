/// Errors that may occur when using the point_addition module
#[derive(Debug, thiserror::Error)]
pub enum PointAdditionError {
    #[error("Protocol error: State {0:?}, Message {1:?}")]
    ProtocolError(
        Box<dyn std::fmt::Debug + Send + 'static>,
        Option<crate::point_addition::PointAdditionMessage>,
    ),
    #[error("Tried to get secret share before protocol was complete")]
    ProtocolIncomplete,
}
