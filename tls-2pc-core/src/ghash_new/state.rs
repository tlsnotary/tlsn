use super::{AddShare, MulShare};

mod sealed {
    pub trait Sealed {}
}

pub trait State: sealed::Sealed {}
pub trait Role: sealed::Sealed {}

pub struct Initialized {
    pub(crate) hashkey: AddShare,
}
impl State for Initialized {}
impl sealed::Sealed for Initialized {}

pub struct MulSharing {
    pub(crate) hashkey: MulShare,
}
impl State for MulSharing {}
impl sealed::Sealed for MulSharing {}

pub struct Sender;
impl Role for Sender {}
impl sealed::Sealed for Sender {}

pub struct Receiver;
impl Role for Receiver {}
impl sealed::Sealed for Receiver {}
