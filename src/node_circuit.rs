use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::{circuit_compiler::CircuitCompiler, tree_proof::Proof};

pub struct NodeCircuit<C, F, P, const D: usize>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
    P: Proof<C, F, D>,
{
    left_child: P,
    right_child: P,
    phantom_data: PhantomData<(C, F)>,
}

impl<C, F, P, const D: usize> NodeCircuit<C, F, P, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
    P: Proof<C, F, D>,
{
    pub fn new(left_child: P, right_child: P) -> Self {
        Self {
            left_child,
            right_child,
            phantom_data: PhantomData,
        }
    }
}

impl<C, F, P, const D: usize> CircuitCompiler<F, D> for NodeCircuit<C, F, P, D>
where
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    P: Proof<C, F, D>,
{
    type Value = (HashOut<F>, HashOut<F>);
    type Targets = [HashOutTarget; 4];
    type OutTargets = (HashOutTarget, HashOutTarget);

    fn compile(
        &self,
        circuit_builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets) {
        let left_child_input_hash_targets = circuit_builder.add_virtual_hash();
        let right_child_input_hash_targets = circuit_builder.add_virtual_hash();
        let node_input_hash_targets = circuit_builder.add_virtual_hash();

        circuit_builder.register_public_inputs(&node_input_hash_targets.elements);

        let should_be_node_input_hash_targets = circuit_builder
            .hash_n_to_hash_no_pad::<<C as GenericConfig<D>>::Hasher>(
                [
                    left_child_input_hash_targets.elements,
                    right_child_input_hash_targets.elements,
                ]
                .concat(),
            );

        circuit_builder.connect_hashes(node_input_hash_targets, should_be_node_input_hash_targets);

        let [left_child_circuit_hash_targets, right_child_circuit_hash_targets, left_child_circuit_verifier_data_hash_targets, right_child_circuit_verifier_data_hash_targets, node_circuit_hash_targets] =
            [circuit_builder.add_virtual_hash(); 5];

        circuit_builder
            .register_public_inputs(&left_child_circuit_verifier_data_hash_targets.elements);
        circuit_builder
            .register_public_inputs(&right_child_circuit_verifier_data_hash_targets.elements);
        circuit_builder.register_public_inputs(&node_circuit_hash_targets.elements);

        circuit_builder.connect_hashes(
            left_child_circuit_verifier_data_hash_targets,
            right_child_circuit_verifier_data_hash_targets,
        );

        let should_be_node_circuit_hash_targets = circuit_builder
            .hash_n_to_hash_no_pad::<<C as GenericConfig<D>>::Hasher>(
                [
                    left_child_circuit_hash_targets.elements,
                    left_child_circuit_verifier_data_hash_targets.elements,
                    right_child_circuit_hash_targets.elements,
                ]
                .concat(),
            );

        circuit_builder.connect_hashes(
            node_circuit_hash_targets,
            should_be_node_circuit_hash_targets,
        );

        // TODO: this can possible be simplified by using the recursive part to verify the circuit verifier digests

        todo!()
    }

    fn evaluate(&self) -> Self::Value {
        todo!()
    }

    fn fill(
        &self,
        partial_witness: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error> {
        todo!()
    }
}
