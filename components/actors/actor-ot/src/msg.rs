//! This module contains message structs which can be sent to the actor to trigger different
//! message handlers.

use mpz_core::Block;
use mpz_ot::kos::{receiver::Kos15IOReceiver, sender::Kos15IOSender};
use mpz_ot_core::{r_state::RandSetup as RandSetupReceiver, s_state::RandSetup as RandSetupSender};
use std::fmt::Debug;

#[derive(Debug)]
pub(crate) struct Setup;

#[derive(Debug)]
pub(crate) struct GetSender {
    pub(crate) id: String,
    pub(crate) count: usize,
}

#[derive(Debug)]
pub(crate) struct GetReceiver {
    pub(crate) id: String,
    pub(crate) count: usize,
}

#[derive(Debug)]
pub(crate) struct Reveal;

pub(crate) struct SendBackSender {
    pub(crate) id: String,
    pub(crate) child_sender: Kos15IOSender<RandSetupSender>,
}

impl Debug for SendBackSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendBackSender")
            .field("id", &self.id)
            .field("child_sender", &"{{ ... }}")
            .finish()
    }
}

pub(crate) struct SendBackReceiver {
    pub(crate) id: String,
    pub(crate) child_receiver: Kos15IOReceiver<RandSetupReceiver>,
}

impl Debug for SendBackReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendBackReceiver")
            .field("id", &self.id)
            .field("child_receiver", &"{{ ... }}")
            .finish()
    }
}

pub(crate) struct Verify {
    pub(crate) id: String,
    pub(crate) input: Vec<[Block; 2]>,
}

impl Debug for Verify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verify")
            .field("id", &self.id)
            .field("input", &"{{ ... }}")
            .finish()
    }
}
