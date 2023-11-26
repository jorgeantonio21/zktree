use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::{GenericConfig, Hasher},
};

use crate::{proof_data::ProofData, traits::proof::Proof};

pub type UserInput<F> = Vec<F>;

/// A struct representing the proof data and associated user inputs for a specific circuit. It
/// encapsulates all necessary information for verifying a user's interaction with a circuit.
///
/// # Type Parameters
///
/// * `C`: The configuration of the circuit, adhering to `GenericConfig`.
/// * `F`: The field type used in the circuit. It must implement `RichField` for cryptographic
///   operations and `Extendable<D>` for field extensions.
/// * `D`: The dimension of the field extension, defined as a compile-time constant.
///
/// # Fields
///
/// * `proof_data`: The proof data generated for the circuit.
/// * `inputs`: A vector of user inputs, each being a vector of field elements.
/// * `user_circuit_hash`: A hash output representing the circuit as used by the user.
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
    pub fn new(
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
        self.inputs.iter().map(AsRef::as_ref).collect::<Vec<_>>()
    }
}
