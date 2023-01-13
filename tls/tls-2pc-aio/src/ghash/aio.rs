use super::{Ghash, GhashIOError};
use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use tls_2pc_core::ghash::{
    state::{Finalized, Init, Intermediate, State},
    GhashCore,
};

/// This is the common instance used by both sender and receiver
///
/// It is an aio wrapper which mostly uses [GhashCore] for computation
pub struct GhashIO<T, U, V: State = Init>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    core: GhashCore<V>,
    pub(crate) a2m_converter: T,
    pub(crate) m2a_converter: U,
}

impl<T, U> GhashIO<T, U, Init>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    /// Creates a new instance
    ///
    /// * `hashkey`             - the key used for Ghash
    /// * `max_message_length`  - the maximum message length for which the Ghash output can be
    ///                           computed
    /// * `a2m_converter`       - An instance which allows to convert additive into multiplicative
    ///                           shares
    /// * `m2a_converter`       - An instance which allows to convert multiplicative into additive
    ///                           shares
    pub fn new(
        hashkey: u128,
        max_message_length: usize,
        a2m_converter: T,
        m2a_converter: U,
    ) -> Result<Self, GhashIOError> {
        let core = GhashCore::new(hashkey, max_message_length)?;
        Ok(Self {
            core,
            a2m_converter,
            m2a_converter,
        })
    }

    /// Setup `self` to be able to generate a Ghash output
    ///
    /// This will perform both conversion steps:
    ///     1. Get a multiplicative share of the hashkey
    ///     2. Compute all necessary additive shares
    pub async fn setup(mut self) -> Result<GhashIO<T, U, Finalized>, GhashIOError> {
        let h_additive = self.core.h_additive();

        let h_multiplicative = self.a2m_converter.a_to_m(vec![h_additive]).await?;
        let core = self.core.compute_odd_mul_powers(h_multiplicative[0]);

        let io = GhashIO {
            core,
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
        };
        io.compute_add_shares().await
    }
}

impl<T, U> GhashIO<T, U, Intermediate>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    /// Computes all the additive share powers
    ///
    /// This assumes that we already have a multiplicative share of the hashkey. So it only
    /// performs the second step. We need this when the message length changes because in this case
    /// we do not need to perform step 1 again.
    pub async fn compute_add_shares(mut self) -> Result<GhashIO<T, U, Finalized>, GhashIOError> {
        let odd_mul_shares = self.core.odd_mul_shares();

        let add_shares = self.m2a_converter.m_to_a(odd_mul_shares).await?;
        let core = self.core.add_new_add_shares(&add_shares);

        let io = GhashIO {
            core,
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
        };
        Ok(io)
    }
}

impl<T, U> GhashIO<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    /// Prepare `self` for a different message length
    ///
    /// We assume here that it is necessary to compute additional share powers. So we go back to
    /// the intermediate state.
    pub fn change_message_length(self, new_message_length: usize) -> GhashIO<T, U, Intermediate> {
        GhashIO {
            core: self.core.change_max_hashkey(new_message_length),
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
        }
    }
}

impl<T, U> Ghash for GhashIO<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    fn generate_ghash(&self, message: &[u128]) -> Result<u128, GhashIOError> {
        self.core.ghash_output(message).map_err(GhashIOError::from)
    }
}
