use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use tls_2pc_core::ghash::{Finalized, GhashCore, Init, Intermediate};

use super::{GhashIOError, GhashOutput};

pub struct GhashIO<T, U, V = Init>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    core: GhashCore<V>,
    a2m_converter: T,
    m2a_converter: U,
    id: String,
}

impl<T, U> GhashIO<T, U, Init>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub fn new(
        hashkey: u128,
        max_message_length: usize,
        a2m_converter: T,
        m2a_converter: U,
        id: String,
    ) -> Result<Self, GhashIOError> {
        let core = GhashCore::new(hashkey, max_message_length)?;
        Ok(Self {
            core,
            a2m_converter,
            m2a_converter,
            id,
        })
    }

    pub async fn setup(mut self) -> Result<GhashIO<T, U, Finalized>, GhashIOError> {
        let h_additive = self.core.h_additive();

        let h_multiplicative = self.a2m_converter.a_to_m(&[h_additive]).await?;
        let core = self.core.compute_odd_mul_powers(h_multiplicative[0]);

        let io = GhashIO {
            core,
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
            id: self.id,
        };
        io.compute_add_shares().await
    }
}

impl<T, U> GhashIO<T, U, Intermediate>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub async fn compute_add_shares(mut self) -> Result<GhashIO<T, U, Finalized>, GhashIOError> {
        let odd_mul_shares = self.core.odd_mul_shares();

        let add_shares = self.m2a_converter.m_to_a(&odd_mul_shares).await?;
        let core = self.core.add_new_add_shares(&add_shares);

        let io = GhashIO {
            core,
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
            id: self.id,
        };
        Ok(io)
    }
}

impl<T, U> GhashIO<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    pub fn change_message_length(self, new_message_length: usize) -> GhashIO<T, U, Intermediate> {
        GhashIO {
            core: self.core.change_max_hashkey(new_message_length),
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
            id: self.id,
        }
    }
}

impl<T, U> GhashOutput for GhashIO<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    fn generate_ghash_output(&self, message: &[u128]) -> Result<u128, GhashIOError> {
        self.core.ghash_output(message).map_err(GhashIOError::from)
    }
}
