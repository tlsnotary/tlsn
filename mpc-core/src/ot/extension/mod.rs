mod kos15;

pub use kos15::receiver::{
    error::ExtReceiverCoreError, BaseSend as RBaseSend, BaseSetup as RBaseSetup,
    Initialized as RInitialized, Kos15Receiver, Setup as RSetup,
};

pub use kos15::sender::{
    error::ExtSenderCoreError, BaseReceive as SBaseReceive, BaseSetup as SBaseSetup,
    Initialized as SInitialized, Kos15Sender, Setup as SSetup,
};

pub use kos15::BASE_COUNT;
