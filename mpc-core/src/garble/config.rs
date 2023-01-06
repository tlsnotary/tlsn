use std::sync::Arc;

use derive_builder::Builder;

use mpc_circuits::{Circuit, InputValue, WireGroup};
use rand::{CryptoRng, Rng};
use utils::iter::DuplicateCheck;

use super::{ActiveInputLabels, Delta, FullInputLabels};

#[derive(Debug, Clone, Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct GarbleConfig {
    pub circ: Arc<Circuit>,
    #[builder(default = "None", setter(strip_option))]
    pub generator_config: Option<GeneratorConfig>,
    #[builder(default = "None", setter(strip_option))]
    pub evaluator_config: Option<EvaluatorConfig>,
}

impl GarbleConfigBuilder {
    /// Generates a config using the provided rng and circuit
    pub fn default_dual_with_rng<R: Rng + CryptoRng>(rng: &mut R, circ: Arc<Circuit>) -> Self {
        let generator_config = GeneratorConfigBuilder::default()
            .with_rng(rng, &circ)
            .build()
            .expect("Default generator config should be valid");

        let evaluator_config = EvaluatorConfigBuilder::default()
            .build()
            .expect("Default evaluator config should be valid");

        let mut config = Self::default();
        config.circ = Some(circ);
        config.generator_config = Some(Some(generator_config));
        config.evaluator_config = Some(Some(evaluator_config));

        config
    }

    fn validate(&self) -> Result<(), String> {
        let Some(ref circ) = self.circ else {
            return Err("Must provide circuit".to_string())
        };

        if let Some(Some(generator_config)) = self.generator_config.as_ref() {
            validate_inputs(circ, &generator_config.input_labels)?;
        }

        if let Some(Some(evaluator_config)) = self.evaluator_config.as_ref() {
            validate_inputs(circ, &evaluator_config.input_labels)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Builder)]
pub struct GeneratorConfig {
    pub input_labels: Vec<FullInputLabels>,
    pub delta: Delta,
}

impl GeneratorConfigBuilder {
    /// Generates a config using the provided rng and circuit
    pub fn with_rng<R: Rng + CryptoRng>(&mut self, rng: &mut R, circ: &Circuit) -> &mut Self {
        let (input_labels, delta) = FullInputLabels::generate_set(rng, circ, None);
        self.input_labels = Some(input_labels);
        self.delta = Some(delta);
        self
    }
}

impl GeneratorConfig {
    /// Returns Generator's input labels
    ///
    /// * `generator_inputs` - Generator's inputs to the circuit
    pub fn generator_labels(&self, generator_inputs: &[impl WireGroup]) -> Vec<FullInputLabels> {
        let gen_input_ids = generator_inputs
            .iter()
            .map(|input| input.id())
            .collect::<Vec<usize>>();

        self.input_labels
            .iter()
            .filter(|input| gen_input_ids.contains(&input.id()))
            .cloned()
            .collect()
    }

    /// Returns Evaluator's input labels by excluding Generator's inputs from the set
    ///
    /// * `generator_inputs` - Generator's inputs to the circuit
    pub fn evaluator_labels(&self, generator_inputs: &[impl WireGroup]) -> Vec<FullInputLabels> {
        let gen_input_ids = generator_inputs
            .iter()
            .map(|input| input.id())
            .collect::<Vec<usize>>();

        self.input_labels
            .iter()
            .filter(|input| !gen_input_ids.contains(&input.id()))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Default, Clone, Builder)]
pub struct EvaluatorConfig {
    #[builder(default = "vec![]")]
    pub input_labels: Vec<ActiveInputLabels>,
}

impl EvaluatorConfig {
    /// Returns only the inputs which the Evaluator still needs to retrieve via OT
    ///
    /// * `inputs` - All of Evaluator's input values
    pub fn filter_cached_inputs(&self, inputs: &[InputValue]) -> Vec<InputValue> {
        let cached_input_ids = self
            .input_labels
            .iter()
            .map(|labels| labels.id())
            .collect::<Vec<usize>>();

        inputs
            .iter()
            .filter(|input| !cached_input_ids.contains(&input.id()))
            .cloned()
            .collect::<Vec<InputValue>>()
    }
}

fn validate_inputs(circ: &Circuit, inputs: &[impl WireGroup]) -> Result<(), String> {
    if inputs
        .iter()
        .map(|input| input.id())
        .collect::<Vec<usize>>()
        .iter()
        .contains_dups()
    {
        return Err("Duplicate inputs".to_string());
    } else if !inputs
        .iter()
        .map(|input| input.id())
        .all(|id| circ.is_input_id(id))
    {
        return Err("Invalid input id".to_string());
    }

    Ok(())
}
