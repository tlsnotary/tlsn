//! Mocks for testing the share conversion protocol.

use super::{ConverterReceiver, ConverterSender, ReceiverConfig, SenderConfig};
use mpc_ot::mock::{mock_ot_pair, MockOTReceiver, MockOTSender};
use mpc_share_conversion_core::fields::Field;
use utils_aio::duplex::DuplexChannel;

/// A mock converter sender
pub type MockConverterSender<F> = ConverterSender<F, MockOTSender>;
/// A mock converter receiver
pub type MockConverterReceiver<F> = ConverterReceiver<F, MockOTReceiver>;

/// Creates a mock sender and receiver for testing the share conversion protocol.
#[allow(clippy::type_complexity)]
pub fn mock_converter_pair<F: Field>(
    sender_config: SenderConfig,
    receiver_config: ReceiverConfig,
) -> (
    ConverterSender<F, MockOTSender>,
    ConverterReceiver<F, MockOTReceiver>,
) {
    let (c1, c2) = DuplexChannel::new();

    let (ot_sender, ot_receiver) = mock_ot_pair();

    let sender = ConverterSender::new(sender_config, ot_sender, Box::new(c1));
    let receiver = ConverterReceiver::new(receiver_config, ot_receiver, Box::new(c2));

    (sender, receiver)
}
