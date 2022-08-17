mod receiver;
mod sender;

pub use receiver::*;
pub use sender::*;

// We instantiate KOS15 w.r.t the DH-OT defined in CO15
pub(crate) use crate::ot::base::dh_ot::{DhOtReceiver as BaseReceiver, DhOtSender as BaseSender};
