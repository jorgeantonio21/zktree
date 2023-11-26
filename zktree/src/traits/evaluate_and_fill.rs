use anyhow::Error;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::witness::PartialWitness,
    plonk::config::GenericConfig,
};

use super::circuit_compiler::CircuitCompiler;

/// The `EvaluateFillCircuit` trait extends the `CircuitCompiler` trait to provide functionality
/// for evaluating a compiled circuit and filling its witness. It is used to both execute the
/// circuit logic to obtain a result and to populate a witness with the necessary data for
/// proof generation and verification.
///
/// # Type Parameters
///
/// * `C`: Configuration for the circuit, implementing `GenericConfig`.
/// * `F`: The field type used in the circuit, which must implement `RichField` and `Extendable<D>`.
/// * `D`: A constant defining the dimension for the field extension.
///
/// # Associated Types
///
/// * `Value`: The type of the value produced by evaluating the circuit.
///
/// # Required Methods
///
/// * `evaluate`: Executes the logic of the circuit and produces a value of type `Self::Value`.
///
/// * `fill`: Given the targets and output targets of a circuit, it populates the partial witness
///   necessary for the circuit's verification.
///
/// # Returns
///
/// * `Result<PartialWitness<F>, Error>`: A result that, on success, contains the `PartialWitness<F>`
///   populated with the circuit's data, or an error if the process fails.
pub trait EvaluateFillCircuit<C, F, const D: usize>: CircuitCompiler<C, F, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    /// The type representing the value obtained from evaluating the circuit.
    type Value;

    /// Evaluates the circuit and produces a result of type `Self::Value`. This method encapsulates
    /// the circuit's logic and computes the output based on the current state of the circuit.
    ///
    /// # Returns
    ///
    /// A value of type `Self::Value` that is the result of the circuit evaluation.
    fn evaluate(&self) -> Self::Value;

    /// Populates a `PartialWitness` based on the provided input and output targets of the circuit.
    /// This is typically used for setting up the witness data that will be used during the circuit's
    /// verification process.
    ///
    /// # Arguments
    ///
    /// * `targets`: The input targets within the circuit.
    /// * `out_targets`: The output targets within the circuit.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains the populated `PartialWitness<F>`, or an `Error` if
    /// filling the witness fails.
    fn fill(
        &self,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<PartialWitness<F>, Error>;
}
