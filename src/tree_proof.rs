use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    plonk::config::GenericConfig,
};

use crate::proof_data::ProofData;

pub trait Proof<C, F, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn user_public_inputs(&self) -> &[&[F]];
    fn circuit_verifier_digest(&self) -> HashOut<F>;
    fn input_hash(&self) -> HashOut<F>;
    fn circuit_hash(&self) -> HashOut<F>;
    fn proof(&self) -> &ProofData<F, C, D>;
}
