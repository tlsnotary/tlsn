use super::Converter;
use mpc_core::Block;
use share_conversion_aio::conversion::{
    mock::{mock_converter_pair, MockReceiver, MockSender},
    recorder::Void,
};
use share_conversion_core::{fields::p256::P256, AddShare, MulShare};

pub type MockPointConversionSender = Converter<
    MockSender<AddShare<P256>, P256, [Block; 2], Void>,
    MockSender<MulShare<P256>, P256, [Block; 2], Void>,
    P256,
>;

pub type MockPointConversionReceiver = Converter<
    MockReceiver<AddShare<P256>, P256, [Block; 2], Void>,
    MockReceiver<MulShare<P256>, P256, [Block; 2], Void>,
    P256,
>;

pub fn create_mock_point_converter_pair() -> (MockPointConversionSender, MockPointConversionReceiver)
{
    let (sender_a2m, receiver_a2m) =
        mock_converter_pair::<AddShare<P256>, P256, [Block; 2], Void>();
    let (sender_m2a, receiver_m2a) =
        mock_converter_pair::<MulShare<P256>, P256, [Block; 2], Void>();

    let sender = MockPointConversionSender::new(sender_a2m, sender_m2a, true);
    let receiver = MockPointConversionReceiver::new(receiver_a2m, receiver_m2a, false);

    (sender, receiver)
}
