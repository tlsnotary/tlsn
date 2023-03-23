use super::{recorder::Recorder, Receiver, Sender, ShareConversionMessage};
use mpc_ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
use mpc_share_conversion_core::{fields::Field, ShareConvert};
use utils_aio::duplex::DuplexChannel;

pub type ShareConversionChannel<T> = DuplexChannel<ShareConversionMessage<T>>;
pub type MockSender<U, V, X, W> = Sender<MockOTFactory<X>, MockOTSender<X>, U, V, X, W>;
pub type MockReceiver<U, V, X, W> = Receiver<MockOTFactory<X>, MockOTReceiver<X>, U, V, X, W>;

pub fn mock_converter_pair<
    U: ShareConvert<Inner = V>,
    V: Field<BlockEncoding = X>,
    X: Send + 'static,
    W: Recorder<U, V>,
>() -> (MockSender<U, V, X, W>, MockReceiver<U, V, X, W>)
where
    MockOTFactory<X>: Clone,
{
    let (c1, c2): (ShareConversionChannel<V>, ShareConversionChannel<V>) = DuplexChannel::new();
    let ot_factory = MockOTFactory::new();

    let sender = MockSender::new(ot_factory.clone(), String::from(""), Box::new(c1), None);
    let receiver = MockReceiver::new(ot_factory, String::from(""), Box::new(c2));

    (sender, receiver)
}
