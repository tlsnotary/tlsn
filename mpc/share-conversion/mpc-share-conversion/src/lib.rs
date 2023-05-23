//! This crate provides a semi-honest protocol (with optional covert-security) for converting secret-shared finite field elements
//! between additive and multiplicative representations.
//!
//! The protocol is based on `Two Party RSA Key Generation [Gil99]` which devised a method for
//! converting additive shares of a finite field element into multiplicative shares (A2M). We use a similar technique
//! to convert multiplicative shares into additive shares (M2A), inspired by `Efficient Secure Two-Party Exponentiation [YCCL11]`.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

use async_trait::async_trait;

mod config;
mod converter;
mod error;
#[cfg(feature = "mock")]
pub mod mock;
mod ot;
mod receiver;
mod sender;
pub(crate) mod tape;

pub use config::{
    ReceiverConfig, ReceiverConfigBuilder, ReceiverConfigBuilderError, SenderConfig,
    SenderConfigBuilder, SenderConfigBuilderError,
};
pub use converter::{
    ConverterReceiver, ConverterReceiverHandle, ConverterSender, ConverterSenderHandle,
};
pub use error::{ShareConversionError, TapeVerificationError};
pub use mpc_share_conversion_core::{
    fields::{gf2_128::Gf2_128, p256::P256, Field},
    msgs::ShareConversionMessage,
};
pub use ot::{OTReceiveElement, OTSendElement};
pub use receiver::GilboaReceiver;
pub use sender::GilboaSender;

use utils_aio::Channel;

/// A channel used by conversion protocols for messaging
pub type ShareConversionChannel<T> = Box<dyn Channel<ShareConversionMessage<T>>>;

/// A trait for converting additive shares into multiplicative shares.
#[async_trait]
pub trait AdditiveToMultiplicative<T: Field> {
    /// Converts additive shares into multiplicative shares
    async fn to_multiplicative(&self, input: Vec<T>) -> Result<Vec<T>, ShareConversionError>;
}

/// A trait for converting multiplicative shares into additive shares.
#[async_trait]
pub trait MultiplicativeToAdditive<T: Field> {
    /// Converts multiplicative shares into additive shares
    async fn to_additive(&self, input: Vec<T>) -> Result<Vec<T>, ShareConversionError>;
}

/// A trait for converting secret-shared finite field elements between additive and multiplicative
/// representations.
pub trait ShareConversion<F: Field>:
    AdditiveToMultiplicative<F> + MultiplicativeToAdditive<F>
{
}

impl<T, F> ShareConversion<F> for T
where
    T: AdditiveToMultiplicative<F> + MultiplicativeToAdditive<F>,
    F: Field,
{
}

/// Send a tape used for verification of the conversion
///
/// Senders record their inputs used during conversion and can send them to the receiver
/// afterwards. This will allow the receiver to use [VerifyTape].
#[async_trait]
pub trait ShareConversionReveal {
    /// Reveals the private inputs of the sender to the receiver for verification.
    async fn reveal(self) -> Result<(), ShareConversionError>;
}

/// Verify the recorded inputs of the sender
///
/// Will check if the conversion worked correctly. This allows to catch a malicious sender but
/// requires that he/she makes use of [SendTape].
#[async_trait]
pub trait ShareConversionVerify {
    /// Verifies all share conversions.
    async fn verify(self) -> Result<(), ShareConversionError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use utils_aio::duplex::DuplexChannel;

    use std::marker::PhantomData;

    use crate::config::{ReceiverConfig, SenderConfig};

    use mpc_ot::mock::mock_ot_pair;
    use mpc_share_conversion_core::{
        fields::{gf2_128::Gf2_128, p256::P256, Field},
        ShareType,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn create_pair<F: Field>() -> (GilboaSender<F>, GilboaReceiver<F>) {
        (
            GilboaSender::new(SenderConfig::builder().id("test").record().build().unwrap()),
            GilboaReceiver::new(
                ReceiverConfig::builder()
                    .id("test")
                    .record()
                    .build()
                    .unwrap(),
            ),
        )
    }

    #[rstest]
    #[case::gf2_add(ShareType::Add, PhantomData::<Gf2_128>)]
    #[case::gf2_mul(ShareType::Mul, PhantomData::<Gf2_128>)]
    #[case::p256_add(ShareType::Add, PhantomData::<P256>)]
    #[case::p256_mul(ShareType::Mul, PhantomData::<P256>)]
    #[tokio::test]
    async fn test_conversion<T: Field>(
        #[case] ty: ShareType,
        #[case] _pd: PhantomData<T>,
        #[values(false, true)] malicious: bool,
    ) {
        let (ot_sender, ot_receiver) = mock_ot_pair();
        let (mut sender_channel, mut receiver_channel) = DuplexChannel::new();
        let (mut sender, mut receiver) = create_pair::<T>();
        let mut rng = ChaCha20Rng::from_seed([0; 32]);

        // Create some random shares
        let sender_shares = (0..16)
            .map(|_| ty.new_share(T::rand(&mut rng)))
            .collect::<Vec<_>>();
        let receiver_shares = (0..16)
            .map(|_| ty.new_share(T::rand(&mut rng)))
            .collect::<Vec<_>>();

        let (sender_converted, receiver_converted) = tokio::try_join!(
            sender.convert_from(&ot_sender, &sender_shares),
            receiver.convert_from(&ot_receiver, &receiver_shares)
        )
        .unwrap();

        // If sender is malicious, we modify the tape to be inconsistent
        if malicious {
            *sender
                .state_mut()
                .tape
                .as_mut()
                .unwrap()
                .inputs
                .last_mut()
                .unwrap() = ty.new_share(T::one());
        }

        let res = tokio::try_join!(
            sender.reveal(&mut sender_channel),
            receiver.verify(&mut receiver_channel)
        );

        if malicious {
            assert!(res.is_err());
        } else {
            assert!(res.is_ok());
        }

        for ((a, b), (x, y)) in sender_shares
            .iter()
            .zip(receiver_shares.iter())
            .zip(sender_converted.iter().zip(receiver_converted.iter()))
        {
            match ty {
                ShareType::Add => {
                    assert_eq!(a.to_inner() + b.to_inner(), x.to_inner() * y.to_inner())
                }
                ShareType::Mul => {
                    assert_eq!(a.to_inner() * b.to_inner(), x.to_inner() + y.to_inner())
                }
            }
        }
    }
}
