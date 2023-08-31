use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{circuit_data::CircuitData, config::GenericConfig, proof::ProofWithPublicInputs},
};

pub struct ProofData<F, C: GenericConfig<D, F = F>, const D: usize>
where
    F: RichField + Extendable<D>,
{
    pub(crate) proof_with_pis: ProofWithPublicInputs<F, C, D>,
    pub(crate) circuit_data: CircuitData<F, C, D>,
}

