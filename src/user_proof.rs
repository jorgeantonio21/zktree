use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::{GenericConfig, Hasher},
};

use crate::{proof_data::ProofData, traits::tree_proof::Proof};

pub type UserInput<F> = Vec<F>;

pub struct UserProof<C, F, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    proof_data: ProofData<F, C, D>,
    inputs: Vec<UserInput<F>>,
    user_circuit_hash: HashOut<F>,
}

impl<C, F, const D: usize> UserProof<C, F, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    fn new(
        inputs: Vec<UserInput<F>>,
        user_circuit_hash: HashOut<F>,
        proof_data: ProofData<F, C, D>,
    ) -> Self {
        Self {
            proof_data,
            inputs,
            user_circuit_hash,
        }
    }
}

impl<C, F, const D: usize> Proof<C, F, D> for UserProof<C, F, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    fn circuit_hash(&self) -> HashOut<F> {
        self.user_circuit_hash
    }

    fn input_hash(&self) -> HashOut<F> {
        PoseidonHash::hash_or_noop(&self.inputs.concat())
    }

    fn circuit_verifier_digest(&self) -> HashOut<F> {
        self.user_circuit_hash
    }

    fn proof(&self) -> &ProofData<F, C, D> {
        &self.proof_data
    }

    fn user_public_inputs(&self) -> Vec<&[F]> {
        self.inputs[..]
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
    }
}
