use super::{aio::GhashIO, Ghash, GhashIOError, VerifyGhash};
use async_trait::async_trait;
use share_conversion_aio::{
    gf2_128::VerifyTape, AdditiveToMultiplicative, MultiplicativeToAdditive,
};
use tls_2pc_core::ghash::{Finalized, Init, Intermediate};

pub struct GhashReceiver<T, U, V = Init>(GhashIO<T, U, V>)
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>;

impl<T, U> GhashReceiver<T, U, Init>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub fn new(
        hashkey: u128,
        max_message_length: usize,
        a2m_converter: T,
        m2a_converter: U,
    ) -> Result<Self, GhashIOError> {
        Ok(Self(GhashIO::new(
            hashkey,
            max_message_length,
            a2m_converter,
            m2a_converter,
        )?))
    }

    pub async fn setup(self) -> Result<GhashReceiver<T, U, Finalized>, GhashIOError> {
        let inner = self.0.setup().await?;
        Ok(GhashReceiver(inner))
    }
}

impl<T, U> GhashReceiver<T, U, Intermediate>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub async fn compute_add_shares(self) -> Result<GhashReceiver<T, U, Finalized>, GhashIOError> {
        let inner = self.0.compute_add_shares().await?;
        Ok(GhashReceiver(inner))
    }
}

impl<T, U> GhashReceiver<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub fn change_message_length(
        self,
        new_message_length: usize,
    ) -> Result<GhashReceiver<T, U, Intermediate>, GhashIOError> {
        let inner = self.0.change_message_length(new_message_length);
        Ok(GhashReceiver(inner))
    }
}

impl<T, U> Ghash for GhashReceiver<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    fn generate_ghash(&self, message: &[u128]) -> Result<u128, GhashIOError> {
        self.0.generate_ghash(message)
    }
}

#[async_trait]
impl<T, U> VerifyGhash for GhashReceiver<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128> + VerifyTape + Send,
    U: MultiplicativeToAdditive<FieldElement = u128> + VerifyTape + Send,
{
    async fn verify(self) -> Result<(), GhashIOError> {
        self.0.a2m_converter.verify_tape().await?;
        self.0.m2a_converter.verify_tape().await?;
        Ok(())
    }
}
