use super::{GenerateGhash, GhashError};
use share_conversion_aio::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use tls_2pc_core::ghash::{
    state::{Finalized, Init, Intermediate, State},
    GhashCore,
};

/// This is the common instance used by both sender and receiver
///
/// It is an aio wrapper which mostly uses [GhashCore] for computation
pub struct Ghash<T, U, V: State = Init>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    core: GhashCore<V>,
    a2m_converter: T,
    m2a_converter: U,
}

impl<T, U> Ghash<T, U, Init>
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
    ) -> Result<Self, GhashError> {
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
    pub async fn setup(mut self) -> Result<Ghash<T, U, Finalized>, GhashError> {
        let h_additive = self.core.h_additive();

        let h_multiplicative = self.a2m_converter.a_to_m(vec![h_additive]).await?;
        let core = self.core.compute_odd_mul_powers(h_multiplicative[0]);

        let ghash = Ghash {
            core,
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
        };
        ghash.compute_add_shares().await
    }
}

impl<T, U> Ghash<T, U, Intermediate>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    /// Computes all the additive share powers
    ///
    /// This assumes that we already have a multiplicative share of the hashkey. So it only
    /// performs the second step. We need this when the message length changes because in this case
    /// we do not need to perform step 1 again.
    pub async fn compute_add_shares(mut self) -> Result<Ghash<T, U, Finalized>, GhashError> {
        let odd_mul_shares = self.core.odd_mul_shares();

        let add_shares = self.m2a_converter.m_to_a(odd_mul_shares).await?;
        let core = self.core.add_new_add_shares(&add_shares);

        let ghash = Ghash {
            core,
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
        };
        Ok(ghash)
    }
}

impl<T, U> Ghash<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    /// Prepare `self` for a different message length
    ///
    /// This function is async because if `new_message_length` is greater than
    /// `self.core.max_message_length`, we need to compute new shares with the other party
    pub async fn change_message_length(
        self,
        new_message_length: usize,
    ) -> Result<Ghash<T, U, Finalized>, GhashError> {
        let ghash = Ghash {
            core: self.core.change_max_hashkey(new_message_length),
            a2m_converter: self.a2m_converter,
            m2a_converter: self.m2a_converter,
        };

        ghash.compute_add_shares().await
    }
}

impl<T, U> GenerateGhash for Ghash<T, U, Finalized>
where
    T: AdditiveToMultiplicative<FieldElement = u128>,
    U: MultiplicativeToAdditive<FieldElement = u128>,
{
    fn finalize(&self, message: &[u128]) -> Result<u128, GhashError> {
        self.core.ghash_output(message).map_err(GhashError::from)
    }
}
