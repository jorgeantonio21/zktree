use std::marker::PhantomData;

use anyhow::Error;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::{AlgebraicHasher, GenericConfig, Hasher},
};

use crate::{
    components::leaf_circuit::LeafCircuit,
    components::user_proof::UserProof,
    proof_data::ProofData,
    traits::{proof::Proof, provable::Provable},
};

/// `LeafProof` is a structure representing a proof for a leaf node in a zkTree.
/// It contains the necessary information for verifying that a user's
/// inputs and circuit commitments are valid within a larger proof system.
///
/// # Type Parameters
///
/// * `C`: The configuration of the circuit, satisfying `GenericConfig`.
/// * `F`: The field type that must implement `RichField` and `Extendable<D>`, used for the circuit's computations.
/// * `H`: The hasher type that implements `AlgebraicHasher<F>`, utilized for generating cryptographic hashes.
/// * `D`: The dimension of the field extension, specified as a compile-time constant.
///
/// # Fields
///
/// * `hash_user_public_inputs`: A cryptographic hash of the user's public inputs.
/// * `user_circuit_hash`: A cryptographic hash representing the user's circuit.
/// * `proof_data`: The proof data related to the user's interactions with the circuit.
/// * `_phantom_data`: `PhantomData` used to mark the usage of the hasher type `H`.
pub struct LeafProof<C, F, H, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    H: AlgebraicHasher<F>,
{
    hash_user_public_inputs: HashOut<F>,
    user_circuit_hash: HashOut<F>,
    proof_data: ProofData<F, C, D>,
    _phantom_data: PhantomData<H>,
}

impl<C, F, H, const D: usize> LeafProof<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    /// Constructs a new `LeafProof` with the given hashes and proof data.
    ///
    /// # Arguments
    ///
    /// * `hash_user_public_inputs`: The hash of the user's public inputs.
    /// * `user_circuit_hash`: The hash of the user's circuit.
    /// * `proof_data`: The proof data generated for the user's interactions with the circuit.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `LeafProof`.
    pub fn new(
        hash_user_public_inputs: HashOut<F>,
        user_circuit_hash: HashOut<F>,
        proof_data: ProofData<F, C, D>,
    ) -> Self {
        Self {
            hash_user_public_inputs,
            user_circuit_hash,
            proof_data,
            _phantom_data: PhantomData,
        }
    }

    /// Constructs a new `LeafProof` from a `UserProof`. It hashes the public inputs, retrieves the
    /// circuit hash from the `UserProof`, and generates proof data.
    ///
    /// # Arguments
    ///
    /// * `user_proof`: A reference to the `UserProof` from which to generate the `LeafProof`.
    ///
    /// # Returns
    ///
    /// Returns a `Result` that is `Ok(Self)` if the `LeafProof` is successfully created, or an `Error` if
    /// any operation within the proof generation fails.
    ///
    /// # Errors
    ///
    /// This function can return an `Error` if the proof data generation fails.
    pub fn new_from_user_proof(user_proof: &UserProof<C, F, D>) -> Result<Self, Error> {
        let user_proof_public_inputs = user_proof.user_public_inputs();
        let hash_user_public_inputs =
            PoseidonHash::hash_or_noop(&user_proof_public_inputs.concat());
        let user_circuit_hash = user_proof.circuit_hash();

        let leaf_circuit = LeafCircuit::new(user_proof);
        let proof_data = leaf_circuit.proof()?;
        Ok(Self {
            hash_user_public_inputs,
            proof_data,
            user_circuit_hash,
            _phantom_data: PhantomData,
        })
    }
}

impl<C, F, H, const D: usize> Proof<C, F, D> for LeafProof<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    fn circuit_hash(&self) -> HashOut<F> {
        let user_circuit_hash = self.user_circuit_hash;
        let circuit_verifier_hash = self.circuit_verifier_digest();
        PoseidonHash::hash_or_noop(
            &[circuit_verifier_hash.elements, user_circuit_hash.elements].concat(),
        )
    }

    fn circuit_verifier_digest(&self) -> HashOut<F> {
        self.proof_data.circuit_data.verifier_only.circuit_digest
    }

    fn input_hash(&self) -> HashOut<F> {
        self.hash_user_public_inputs
    }

    fn proof(&self) -> &ProofData<F, C, D> {
        &self.proof_data
    }

    fn user_public_inputs(&self) -> Vec<&[F]> {
        vec![]
    }
}
