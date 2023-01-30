use super::{recorder::Recorder, Receiver, Sender, ShareConversionMessage};
use mpc_aio::protocol::ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
use mpc_core::Block;
use share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::duplex::DuplexChannel;

pub type ShareConversionChannel<T> = DuplexChannel<ShareConversionMessage<T>>;
pub type MockSender<U, V, X, W> = Sender<MockOTFactory<X>, MockOTSender<X>, U, V, X, W>;
pub type MockReceiver<U, V, W> = Receiver<MockOTFactory<Block>, MockOTReceiver<Block>, U, V, W>;

pub fn mock_converter_pair<
    U: ShareConvert<Inner = V>,
    V: Field<OTEncoding = X>,
    X: Send + 'static,
    W: Recorder<U, V>,
>() -> (MockSender<U, V, X, W>, MockReceiver<U, V, W>) {
    let (c1, c2): (ShareConversionChannel<V>, ShareConversionChannel<V>) = DuplexChannel::new();
    let ot_factory = MockOTFactory::new();
    let ot_factory2 = MockOTFactory::<Block>::new();

    let sender = MockSender::new(ot_factory, String::from(""), Box::new(c1), None);
    let receiver = MockReceiver::new(ot_factory2, String::from(""), Box::new(c2));

    (sender, receiver)
}
