use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitData, config::GenericConfig},
};

/// A trait for compiling circuits, parameterized over a configuration `C`, a field `F`, and a
/// dimension `D`. This trait is designed for zk-SNARK circuits, allowing for compilation and
/// construction of proofs without revealing the underlying data.
///
/// # Type Parameters
///
/// * `C`: Represents the configuration for the circuit, must satisfy `GenericConfig`.
/// * `F`: The field type that must implement `RichField` for cryptographic operations and
///        `Extendable<D>` for field extensions.
/// * `D`: A compile-time constant that defines the dimension of the field extension.
///
/// # Associated Types
///
/// * `Targets`: The type representing the internal targets within the circuit for inputs.
/// * `OutTargets`: The type representing the external targets within the circuit for outputs.
pub trait CircuitCompiler<C, F, const D: usize>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    /// The type representing targets within the circuit.
    type Targets;
    /// The type representing output targets within the circuit.
    type OutTargets;

    /// Compiles the circuit into a constructible format using a `CircuitBuilder` and provides
    /// the associated input and output targets. The circuit is not finalized at this stage.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `CircuitBuilder<F, D>`: A builder for constructing the circuit step by step.
    /// - `Self::Targets`: The input targets for the circuit.
    /// - `Self::OutTargets`: The output targets for the circuit.
    fn compile(&self) -> (CircuitBuilder<F, D>, Self::Targets, Self::OutTargets);

    /// Compiles and builds the circuit, providing the circuit data and
    /// associated input and output targets.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `CircuitData<F, C, D>`: The finalized data of the compiled circuit.
    /// - `Self::Targets`: The input targets for the circuit.
    /// - `Self::OutTargets`: The output targets for the circuit.
    ///
    /// # Mutability
    ///
    /// Consumes a mutable reference to self, which may alter the compiler's state.
    fn compile_and_build(&mut self) -> (CircuitData<F, C, D>, Self::Targets, Self::OutTargets);
}
