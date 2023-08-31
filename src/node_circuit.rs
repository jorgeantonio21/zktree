use std::marker::PhantomData;

use anyhow::Error;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
    },
};

use crate::{
    circuit_compiler::CircuitCompiler, proof_data::ProofData, provable::Provable, tree_proof::Proof,
};

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
        circuit_builder: &mut CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets) {
        // targets for recursive proof verification
        let left_proof_with_pis_targets = circuit_builder
            .add_virtual_proof_with_pis(&self.left_child.proof().circuit_data.common);

        let left_verifier_data_targets = circuit_builder.add_virtual_verifier_data(
            self.left_child
                .proof()
                .circuit_data
                .common
                .config
                .fri_config
                .cap_height,
        );

        circuit_builder.verify_proof::<C>(
            &left_proof_with_pis_targets,
            &left_verifier_data_targets,
            &self.left_child.proof().circuit_data.common,
        );

        let right_proof_with_pis_targets = circuit_builder
            .add_virtual_proof_with_pis(&self.right_child.proof().circuit_data.common);

        let right_verifier_data_targets = circuit_builder.add_virtual_verifier_data(
            self.right_child
                .proof()
                .circuit_data
                .common
                .config
                .fri_config
                .cap_height,
        );

        // input hash digest verifications
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

        let [left_child_circuit_hash_targets, right_child_circuit_hash_targets, node_circuit_hash_targets] =
            [circuit_builder.add_virtual_hash(); 3];

        circuit_builder.register_public_inputs(&node_circuit_hash_targets.elements);

        // the two child circuit digests must be the same
        circuit_builder.connect_hashes(
            left_verifier_data_targets.circuit_digest,
            right_verifier_data_targets.circuit_digest,
        );

        let should_be_node_circuit_hash_targets = circuit_builder
            .hash_n_to_hash_no_pad::<<C as GenericConfig<D>>::Hasher>(
                [
                    left_child_circuit_hash_targets.elements,
                    left_verifier_data_targets.circuit_digest.elements,
                    right_child_circuit_hash_targets.elements,
                ]
                .concat(),
            );

        circuit_builder.connect_hashes(
            node_circuit_hash_targets,
            should_be_node_circuit_hash_targets,
        );

        // public inputs verification
        let true_bool_target = circuit_builder._true();
        let false_bool_target = circuit_builder._false();

        if left_proof_with_pis_targets.public_inputs.len() != 8 {
            circuit_builder.connect(true_bool_target.target, false_bool_target.target);
        }

        (0..4).for_each(|i| {
            circuit_builder.connect(
                left_proof_with_pis_targets.public_inputs[i],
                left_child_input_hash_targets.elements[i],
            )
        });

        (4..8).for_each(|i| {
            circuit_builder.connect(
                left_proof_with_pis_targets.public_inputs[i],
                left_child_circuit_hash_targets.elements[i],
            )
        });

        if right_proof_with_pis_targets.public_inputs.len() != 8 {
            circuit_builder.connect(true_bool_target.target, false_bool_target.target);
        }

        (0..4).for_each(|i| {
            circuit_builder.connect(
                right_proof_with_pis_targets.public_inputs[i],
                right_child_input_hash_targets.elements[i],
            )
        });

        (4..8).for_each(|i| {
            circuit_builder.connect(
                right_proof_with_pis_targets.public_inputs[i],
                right_child_circuit_hash_targets.elements[i],
            )
        });

        // TODO: Need to add a check that the circuit digest agrees with the left and right childs

        (
            [
                left_child_input_hash_targets,
                right_child_input_hash_targets,
                left_child_circuit_hash_targets,
                right_child_circuit_hash_targets,
            ],
            (node_input_hash_targets, node_circuit_hash_targets),
        )
    }

    fn evaluate(&self) -> Self::Value {
        todo!()
    }

    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error> {
        let [left_child_input_hash_targets, right_child_input_hash_targets, left_child_circuit_hash_targets, right_child_circuit_hash_targets] =
            targets;
        let (node_input_hash_targets, node_circuit_hash_targets) = out_targets;

        partial_witness.set_hash_target(
            left_child_circuit_hash_targets,
            self.left_child.circuit_hash(),
        );
        todo!()
    }
}

impl<C, F, P, const D: usize> Provable<F, C, D> for NodeCircuit<C, F, P, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
    P: Proof<C, F, D>,
{
    fn proof(self) -> Result<ProofData<F, C, D>, Error> {
        todo!()
    }
}
