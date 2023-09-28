use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitData, config::GenericConfig},
};

pub trait CircuitCompiler<C, F, const D: usize>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    type Targets;
    type OutTargets;

    fn compile(&self) -> (CircuitBuilder<F, D>, Self::Targets, Self::OutTargets);

    fn compile_and_build(&mut self) -> (CircuitData<F, C, D>, Self::Targets, Self::OutTargets);
}
