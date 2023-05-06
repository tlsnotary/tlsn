use std::sync::Arc;

use super::{Receiver, ReceiverConfig, Sender, SenderConfig, ShareConversionMessage};
use mpc_ot::mock::mock_ot_pair;
use mpc_share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::duplex::DuplexChannel;

pub type ShareConversionChannel<T> = DuplexChannel<ShareConversionMessage<T>>;

pub fn mock_converter_pair<T: ShareConvert<Inner = F>, F: Field>(
    sender_config: SenderConfig,
    receiver_config: ReceiverConfig,
) -> (Sender<T, F>, Receiver<T, F>) {
    let (c1, c2): (ShareConversionChannel<F>, ShareConversionChannel<F>) = DuplexChannel::new();

    let (ot_sender, ot_receiver) = mock_ot_pair();

    let sender = Sender::new(sender_config, Arc::new(ot_sender), Box::new(c1), None);
    let receiver = Receiver::new(receiver_config, Arc::new(ot_receiver), Box::new(c2));

    (sender, receiver)
}
