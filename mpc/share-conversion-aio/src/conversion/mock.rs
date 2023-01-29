use super::{recorder::Recorder, Receiver, Sender, ShareConversionMessage};
use mpc_aio::protocol::ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
use mpc_core::Block;
use share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::duplex::DuplexChannel;

pub type ShareConversionChannel = DuplexChannel<ShareConversionMessage>;
pub type MockSender<U, V> = Sender<MockOTFactory<Block>, MockOTSender<Block>, U, V>;
pub type MockReceiver<U, V> = Receiver<MockOTFactory<Block>, MockOTReceiver<Block>, U, V>;

pub fn mock_converter_pair<U: ShareConvert<Inner = W>, V: Recorder<U, W>, W: Field>(
) -> (MockSender<U, V>, MockReceiver<U, V>) {
    let (c1, c2): (ShareConversionChannel, ShareConversionChannel) = DuplexChannel::new();
    let ot_factory = MockOTFactory::new();

    let sender = MockSender::new(ot_factory.clone(), String::from(""), Box::new(c1), None);
    let receiver = MockReceiver::new(ot_factory, String::from(""), Box::new(c2));

    (sender, receiver)
}
