use mpc_garble_core::{ActiveInputSet, FullInputSet};

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Initialized {}
    impl Sealed for super::LabelSetup {}
}

pub trait State: sealed::Sealed {}

pub struct Initialized;

pub struct LabelSetup {
    pub(crate) gen_labels: FullInputSet,
    pub(crate) ev_labels: ActiveInputSet,
}

impl State for Initialized {}
impl State for LabelSetup {}
