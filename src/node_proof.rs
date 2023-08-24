use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::proof_data::ProofData;

pub struct NodeProof<C, F, H, const D: usize>
where
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    proof_data: ProofData<F, C, D>,
    input_hash: H,
    circuit_hash: H,
}
