use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::proof_data::ProofData;

pub struct LeafProof<C, F, H, const D: usize>
where
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    input_hash: H,
    circuit_hash: H,
    proof_data: ProofData<F, C, D>,
}

impl<C, F, H, const D: usize> LeafProof<C, F, H, D>
where
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new(input_hash: H, circuit_hash: H, proof_data: ProofData<F, C, D>) -> Self {
        Self {
            input_hash,
            circuit_hash,
            proof_data,
        }
    }

    pub fn new_from_user_proof() {}
}