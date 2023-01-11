use super::{aio::GhashIO, Ghash, GhashIOError, VerifyGhash};
use async_trait::async_trait;
use share_conversion_aio::{gf2_128::SendTape, AdditiveToMultiplicative, MultiplicativeToAdditive};
use tls_2pc_core::ghash::state::{Finalized, Init, Intermediate, State};

pub struct GhashSender<T, U, V: State = Init>(GhashIO<T, U, V>)
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>;

impl<T, U> GhashSender<T, U, Init>
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

    pub async fn setup(self) -> Result<GhashSender<T, U, Finalized>, GhashIOError> {
        let inner = self.0.setup().await?;
        Ok(GhashSender(inner))
    }
}

impl<T, U> GhashSender<T, U, Intermediate>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub async fn compute_add_shares(self) -> Result<GhashSender<T, U, Finalized>, GhashIOError> {
        let inner = self.0.compute_add_shares().await?;
        Ok(GhashSender(inner))
    }
}

impl<T, U> GhashSender<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub fn change_message_length(
        self,
        new_message_length: usize,
    ) -> Result<GhashSender<T, U, Intermediate>, GhashIOError> {
        let inner = self.0.change_message_length(new_message_length);
        Ok(GhashSender(inner))
    }
}

impl<T, U> Ghash for GhashSender<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    fn generate_ghash(&self, message: &[u128]) -> Result<u128, GhashIOError> {
        self.0.generate_ghash(message)
    }
}

#[async_trait]
impl<T, U> VerifyGhash for GhashSender<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128> + SendTape + Send,
    U: MultiplicativeToAdditive<FieldElement = u128> + SendTape + Send,
{
    async fn verify(self) -> Result<(), GhashIOError> {
        self.0.a2m_converter.send_tape().await?;
        self.0.m2a_converter.send_tape().await?;
        Ok(())
    }
}
