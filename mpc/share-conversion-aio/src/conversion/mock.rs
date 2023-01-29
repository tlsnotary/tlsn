use super::{recorder::Recorder, Receiver, Sender, ShareConversionMessage};
use mpc_aio::protocol::ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
use mpc_core::Block;
use share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::duplex::DuplexChannel;

pub type ShareConversionChannel<T> = DuplexChannel<ShareConversionMessage<T>>;
pub type MockSender<U, V, W> = Sender<MockOTFactory<Block>, MockOTSender<Block>, U, V, W>;
pub type MockReceiver<U, V, W> = Receiver<MockOTFactory<Block>, MockOTReceiver<Block>, U, V, W>;

pub fn mock_converter_pair<U: ShareConvert<Inner = V>, V: Field, W: Recorder<U, V>>(
) -> (MockSender<U, V, W>, MockReceiver<U, V, W>) {
    let (c1, c2): (ShareConversionChannel<V>, ShareConversionChannel<V>) = DuplexChannel::new();
    let ot_factory = MockOTFactory::new();

    let sender = MockSender::new(ot_factory.clone(), String::from(""), Box::new(c1), None);
    let receiver = MockReceiver::new(ot_factory, String::from(""), Box::new(c2));

    (sender, receiver)
}
