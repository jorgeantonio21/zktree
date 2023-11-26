use crate::{
    proof_data::ProofData,
    traits::{circuit_compiler::CircuitCompiler, evaluate_and_fill::EvaluateFillCircuit},
};
use anyhow::Error;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};

/// `Provable` is a trait that encapsulates the functionality required to generate and verify a proof
/// for a circuit. It extends `CircuitCompiler` and `EvaluateFillCircuit` to include the entire
/// lifecycle of a zk-SNARK proof, from compilation to verification. This trait is generic over a field `F`,
/// a circuit configuration `C`, and a dimension `D`.
///
/// # Type Parameters
///
/// * `F`: The field type that the circuit operates over. It must be a `RichField` that supports the
///   necessary cryptographic operations and `Extendable<D>` to allow for field extensions.
/// * `C`: The configuration of the circuit, implementing `GenericConfig`.
/// * `D`: The dimension of the field extension, defined as a constant.
///
/// # Constraints
///
/// The trait is bound by `Self: Sized`, ensuring that it can only be implemented by types with a known size at compile time.
///
/// # Required Methods
///
/// * `proof`: Consumes the implementor to produce a `ProofData` or an error. This method is the
///   final step in the proof generation process, outputting the data needed for verification.
///
/// # Provided Methods
///
/// * `prove_and_verify`: A convenience method that both generates a proof and immediately verifies it.
///   It leverages `proof` to generate the proof data and then verifies it using the `verify` method
///   from the `ProofData`'s associated circuit data. This is a complete lifecycle for a zk-SNARK proof
///   within a single method call.
///
/// # Returns
///
/// * `Result<(), Error>`: Returns `Ok(())` if the proof is successfully generated and verified, or
///   an `Error` if any step in the process fails.
pub trait Provable<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>:
    CircuitCompiler<C, F, D> + EvaluateFillCircuit<C, F, D>
where
    Self: Sized,
{
    /// Generates the proof data for the circuit. This method consumes the implementor and is
    /// intended to be called once all the necessary steps to compile and evaluate the circuit have
    /// been completed.
    ///
    /// # Returns
    ///
    /// A `Result` that contains `ProofData<F, C, D>` on success, or an `Error` if proof generation fails.
    fn proof(self) -> Result<ProofData<F, C, D>, Error>;

    /// Generates and verifies a proof for the circuit. It is a convenience method that wraps the
    /// process of proof generation and verification into a single call. It first calls `proof` to
    /// generate the proof data, then verifies the proof. This method consumes the implementor.
    ///
    /// # Returns
    ///
    /// A `Result` that is `Ok(())` if the proof is successfully generated and verified, or an
    /// `Error` if there is a failure in either proof generation or verification.
    fn prove_and_verify(self) -> Result<(), Error> {
        let proof_data = self.proof()?;
        proof_data.circuit_data.verify(proof_data.proof_with_pis)
    }
}
