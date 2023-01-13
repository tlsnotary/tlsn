use super::{recorder::Recorder, Gf2ConversionMessage, Receiver, Sender};
use mpc_aio::protocol::ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
use mpc_core::Block;
use share_conversion_core::gf2_128::Gf2_128ShareConvert;
use std::sync::{Arc, Mutex};
use utils_aio::duplex::DuplexChannel;

pub type Gf2ConversionChannel = DuplexChannel<Gf2ConversionMessage>;
pub type Gf2Sender<U, V> = Sender<Arc<Mutex<MockOTFactory<Block>>>, MockOTSender<Block>, U, V>;
pub type Gf2Receiver<U, V> =
    Receiver<Arc<Mutex<MockOTFactory<Block>>>, MockOTReceiver<Block>, U, V>;

pub fn mock_converter_pair<U: Gf2_128ShareConvert, V: Recorder<U>>(
) -> (Gf2Sender<U, V>, Gf2Receiver<U, V>) {
    let (c1, c2): (Gf2ConversionChannel, Gf2ConversionChannel) = DuplexChannel::new();
    let ot_factory = Arc::new(Mutex::new(MockOTFactory::<Block>::default()));

    let sender = Sender::new(
        Arc::clone(&ot_factory),
        String::from(""),
        Box::new(c1),
        None,
    );
    let receiver = Receiver::new(Arc::clone(&ot_factory), String::from(""), Box::new(c2));

    (sender, receiver)
}
