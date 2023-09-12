use anyhow::Error;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::{proof_data::ProofData, tree_proof::Proof};

pub struct LeafProof<C, F, H, const D: usize>
where
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    hash_user_public_inputs: H,
    user_circuit_hash: H,
    proof_data: ProofData<F, C, D>,
}

impl<C, F, H, const D: usize> LeafProof<C, F, H, D>
where
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new(
        hash_user_public_inputs: H,
        user_circuit_hash: H,
        proof_data: ProofData<F, C, D>,
    ) -> Self {
        Self {
            hash_user_public_inputs,
            user_circuit_hash,
            proof_data,
        }
    }

    pub fn new_from_user_proof<P: Proof<C, F, D>>(user_proof: P) -> Result<Self, Error> {
        let user_proof_public_inputs = user_proof.user_public_inputs();
        // let hash_user_public_inputs = PoseidonHash::hash_or_noop::<H>(&user_proof_public_inputs);
        todo!()
    }
}
