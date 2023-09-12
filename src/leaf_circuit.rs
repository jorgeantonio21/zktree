use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{circuit_compiler::CircuitCompiler, tree_proof::Proof};

pub struct LeafCircuit<C, F, H, P, const D: usize>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    P: Proof<C, F, D>,
{
    user_proof: P,
    verifier_circuit_digest: Option<H::Hash>,
    phantom_data: PhantomData<(C, F)>,
}

impl<C, F, H, P, const D: usize> LeafCircuit<C, F, H, P, D>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    P: Proof<C, F, D>,
{
    pub fn new(user_proof: P) -> Self {
        Self {
            user_proof,
            verifier_circuit_digest: None,
            phantom_data: PhantomData,
        }
    }
}

impl<C, F, H, P, const D: usize> CircuitCompiler<C, F, D> for LeafCircuit<C, F, H, P, D>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
    P: Proof<C, F, D>,
{
    type Targets = (Vec<Target>, [HashOutTarget; 3], VerifierCircuitTarget); // [HashOutTarget; 4];
    type OutTargets = (HashOutTarget, HashOutTarget);

    fn compile(&self) -> (CircuitBuilder<F, D>, Self::Targets, Self::OutTargets) {
        let mut circuit_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

        // add targets for hash <- user public inputs
        let user_public_inputs = self.user_proof.user_public_inputs();
        let user_public_inputs_targets = (0..user_public_inputs.len())
            .map(|i| {
                let len_ith_user_input = user_public_inputs[i].len();
                (0..len_ith_user_input)
                    .map(|j| circuit_builder.add_virtual_target())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let hash_user_public_inputs = circuit_builder.add_virtual_hash();

        // register public inputs
        circuit_builder.register_public_inputs(&hash_user_public_inputs.elements);

        let flatten_user_public_inputs_targets = user_public_inputs_targets
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let should_be_hash_user_public_inputs =
            circuit_builder.hash_or_noop::<H>(flatten_user_public_inputs_targets.clone());

        circuit_builder.connect_hashes(should_be_hash_user_public_inputs, hash_user_public_inputs);

        // circuit hash verification
        let user_verifier_circuit_digest_targets = circuit_builder.add_virtual_hash();
        let verifier_circuit_digest_targets = circuit_builder.add_virtual_hash();

        let leaf_circuit_hash_targets = circuit_builder.add_virtual_hash();

        circuit_builder.register_public_inputs(&leaf_circuit_hash_targets.elements);

        let should_be_leaf_circuit_hash_targets = circuit_builder.hash_or_noop::<H>(
            [
                user_verifier_circuit_digest_targets.elements,
                verifier_circuit_digest_targets.elements,
            ]
            .concat(),
        );

        circuit_builder.connect_hashes(
            leaf_circuit_hash_targets,
            should_be_leaf_circuit_hash_targets,
        );

        // User proof verification
        let user_proof_with_pis_targets = circuit_builder
            .add_virtual_proof_with_pis(&self.user_proof.proof().circuit_data.common);
        let user_verifier_data_targets = circuit_builder.add_virtual_verifier_data(
            self.user_proof
                .proof()
                .circuit_data
                .common
                .fri_params
                .config
                .cap_height,
        );

        circuit_builder.verify_proof::<C>(
            &user_proof_with_pis_targets,
            &user_verifier_data_targets,
            &self.user_proof.proof().circuit_data.common,
        );

        // User proof public inputs verification
        let true_bool_target = circuit_builder._true();
        let false_bool_target = circuit_builder._false();

        if flatten_user_public_inputs_targets.len()
            != user_proof_with_pis_targets.public_inputs.len()
        {
            circuit_builder.connect(true_bool_target.target, false_bool_target.target);
        }

        (0..flatten_user_public_inputs_targets.len()).for_each(|i| {
            circuit_builder.connect(
                user_proof_with_pis_targets.public_inputs[i],
                flatten_user_public_inputs_targets[i],
            );
        });

        (
            circuit_builder,
            (
                flatten_user_public_inputs_targets,
                [
                    hash_user_public_inputs,
                    user_verifier_circuit_digest_targets,
                    verifier_circuit_digest_targets,
                ],
                user_verifier_data_targets,
            ),
            (hash_user_public_inputs, leaf_circuit_hash_targets),
        )
    }

    fn compile_and_build(&mut self) -> (CircuitData<F, C, D>, Self::Targets, Self::OutTargets) {
        todo!()
    }
}
