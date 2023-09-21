use anyhow::Error;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::witness::PartialWitness,
    plonk::config::GenericConfig,
};

use super::circuit_compiler::CircuitCompiler;

pub trait EvaluateFillCircuit<C, F, const D: usize>: CircuitCompiler<C, F, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    type Value;

    fn evaluate(&self) -> Self::Value;
    fn fill(
        &self,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<PartialWitness<F>, Error>;
}
