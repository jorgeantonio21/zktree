use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    plonk::config::GenericConfig,
};

use crate::proof_data::ProofData;

/// The `Proof` trait provides an abstraction over the proof generation process
/// for a given circuit. It is designed to encapsulate the
/// proof data associated with a circuit and to provide methods to access various components of the
/// proof such as public inputs, circuit and input hashes, and the proof data itself.
///
/// # Type Parameters
///
/// * `F`: The field type used in the circuit, implementing `RichField` for cryptographic operations
///        and `Extendable<D>` for field extensions.
/// * `C`: The circuit configuration, satisfying `GenericConfig`.
/// * `D`: A compile-time constant that defines the dimension of the field extension.
///
/// # Methods
///
/// * `user_public_inputs`: Retrieves the public inputs provided by the user for the proof.
///
/// * `circuit_verifier_digest`: Obtains the digest that represents the compiled circuit verifier.
///
/// * `input_hash`: Computes a hash of the public and private inputs to the circuit.
///
/// * `circuit_hash`: Returns a hash representing the circuit itself.
///
/// * `proof`: Accesses the `ProofData` which contains all the necessary information for proof verification.
pub trait Proof<C, F, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// Retrieves a vector of slices, each slice representing a set of public inputs provided by
    /// the user for the proof. Public inputs are elements in the field `F` and are used during the
    /// proof verification process.
    ///
    /// # Returns
    ///
    /// A vector of slices of field elements, each slice representing a set of public inputs.
    fn user_public_inputs(&self) -> Vec<&[F]>;
    /// Obtains the digest of the circuit verifier. This is a hash output that uniquely represents
    /// the compiled circuit verifier, used to ensure that the verification process corresponds to
    /// the correct circuit.
    ///
    /// # Returns
    ///
    /// A `HashOut<F>` representing the digest of the circuit verifier.
    fn circuit_verifier_digest(&self) -> HashOut<F>;
    /// Computes and returns a hash of the inputs to the circuit. This typically includes both the
    /// public and private inputs and is used as part of the proof to ensure integrity of the input data.
    ///
    /// # Returns
    ///
    /// A `HashOut<F>` representing the hash of the circuit inputs.
    fn input_hash(&self) -> HashOut<F>;
    /// Returns a hash that represents the circuit. This hash is used in the verification process to
    /// match the proof against the correct circuit.
    ///
    /// # Returns
    ///
    /// A `HashOut<F>` that is a hash representation of the circuit.
    fn circuit_hash(&self) -> HashOut<F>;
    /// Accesses the proof data associated with the circuit. The `ProofData` structure contains all
    /// the necessary information required to verify the proof.
    ///
    /// # Returns
    ///
    /// A reference to the `ProofData<F, C, D>` which contains the proof information.
    fn proof(&self) -> &ProofData<F, C, D>;
}
