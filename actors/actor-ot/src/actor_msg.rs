use mpc_core::Block;
use mpc_ot::kos::{receiver::Kos15IOReceiver, sender::Kos15IOSender};
use mpc_ot_core::{r_state::RandSetup as RandSetupReceiver, s_state::RandSetup as RandSetupSender};

pub struct Setup;

pub struct GetSender {
    pub id: String,
    pub count: usize,
}

pub struct GetReceiver {
    pub id: String,
    pub count: usize,
}

pub struct MarkForReveal(pub String);

pub struct Reveal;

pub struct SendBackSender {
    pub id: String,
    pub child_sender: Kos15IOSender<RandSetupSender>,
}

pub struct SendBackReceiver {
    pub id: String,
    pub child_receiver: Kos15IOReceiver<RandSetupReceiver>,
}

pub struct Verify {
    pub id: String,
    pub input: Vec<[Block; 2]>,
}
