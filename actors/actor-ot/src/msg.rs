//! This module contains message structs which can be sent to the actor to trigger different
//! message handlers.

use mpc_core::Block;
use mpc_ot::kos::{receiver::Kos15IOReceiver, sender::Kos15IOSender};
use mpc_ot_core::{r_state::RandSetup as RandSetupReceiver, s_state::RandSetup as RandSetupSender};

pub(crate) struct Setup;

pub(crate) struct GetSender {
    pub(crate) id: String,
    pub(crate) count: usize,
}

pub(crate) struct GetReceiver {
    pub(crate) id: String,
    pub(crate) count: usize,
}

pub(crate) struct MarkForReveal(pub(crate) String);

pub(crate) struct Reveal;

pub(crate) struct SendBackSender {
    pub(crate) id: String,
    pub(crate) child_sender: Kos15IOSender<RandSetupSender>,
}

pub(crate) struct SendBackReceiver {
    pub(crate) id: String,
    pub(crate) child_receiver: Kos15IOReceiver<RandSetupReceiver>,
}

pub(crate) struct Verify {
    pub(crate) id: String,
    pub(crate) input: Vec<[Block; 2]>,
}
