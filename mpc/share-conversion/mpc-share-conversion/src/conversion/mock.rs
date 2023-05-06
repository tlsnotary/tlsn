use std::sync::Arc;

use super::{Receiver, ReceiverConfig, Sender, SenderConfig, ShareConversionMessage};
use mpc_ot::mock::mock_ot_pair;
use mpc_share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::duplex::DuplexChannel;

pub type ShareConversionChannel<T> = DuplexChannel<ShareConversionMessage<T>>;
pub type MockSender<U, V, X> = Sender<U, V, X>;
pub type MockReceiver<U, V, X> = Receiver<U, V, X>;

pub fn mock_converter_pair<
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
    X: Send + Copy + std::fmt::Debug + 'static,
>(
    sender_config: SenderConfig,
    receiver_config: ReceiverConfig,
) -> (MockSender<U, V, X>, MockReceiver<U, V, X>) {
    let (c1, c2): (ShareConversionChannel<V>, ShareConversionChannel<V>) = DuplexChannel::new();

    let (ot_sender, ot_receiver) = mock_ot_pair();

    let sender = MockSender::new(sender_config, Arc::new(ot_sender), Box::new(c1), None);
    let receiver = MockReceiver::new(receiver_config, Arc::new(ot_receiver), Box::new(c2));

    (sender, receiver)
}
