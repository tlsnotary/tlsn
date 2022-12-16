use mpc_aio::protocol::ot::{OTSenderFactory, ObliviousSend};
use share_conversion_aio::gf2_128::{
    recorder::{Recorder, Void},
    Gf2ConversionMessage, Sender as IOSender,
};
use share_conversion_core::gf2_128::{Gf2_128ShareConvert, OTEnvelope};
use utils_aio::{adaptive_barrier::AdaptiveBarrier, mux::MuxChannelControl};

use crate::ActorConversionError;

#[derive(xtra::Actor)]
pub struct Sender<T, U, V = Void>
where
    T: OTSenderFactory,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    inner: IOSender<T, U, V>,
}

impl<T, U, V> Sender<T, U, V>
where
    T: OTSenderFactory + Send,
    <<T as OTSenderFactory>::Protocol as ObliviousSend>::Inputs: From<OTEnvelope> + Send,
    U: Gf2_128ShareConvert,
    V: Recorder<U>,
{
    pub async fn new<W: MuxChannelControl<Gf2ConversionMessage>>(
        mut muxer: W,
        sender_factory: T,
        id: String,
        barrier: Option<AdaptiveBarrier>,
    ) -> Result<Self, ActorConversionError> {
        let channel = muxer.get_channel(id.clone()).await?;
        let sender = IOSender::new(sender_factory, id, channel, barrier);
        Ok(Self { inner: sender })
    }
}
