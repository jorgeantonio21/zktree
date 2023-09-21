use anyhow::anyhow;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig, Hasher},
    },
};
use std::marker::PhantomData;

use crate::{
    proof_data::ProofData,
    traits::{
        circuit_compiler::{CircuitCompiler, EvaluateFillCircuit},
        provable::Provable,
        tree_proof::Proof,
    },
    user_proof::UserProof,
};

pub struct LeafCircuit<C, F, H, const D: usize>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    user_proof: UserProof<C, F, D>,
    verifier_circuit_digest: Option<H::Hash>,
    phantom_data: PhantomData<(C, F)>,
}

impl<C, F, H, const D: usize> LeafCircuit<C, F, H, D>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    pub fn new(user_proof: UserProof<C, F, D>) -> Self {
        Self {
            user_proof,
            verifier_circuit_digest: None,
            phantom_data: PhantomData,
        }
    }
}

impl<C, F, H, const D: usize> CircuitCompiler<C, F, D> for LeafCircuit<C, F, H, D>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    type Targets = (Vec<Target>, [HashOutTarget; 3], VerifierCircuitTarget); // [HashOutTarget; 4];
    type OutTargets = HashOutTarget;

    fn compile(&self) -> (CircuitBuilder<F, D>, Self::Targets, Self::OutTargets) {
        let mut circuit_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

        // add targets for hash <- user public inputs
        let user_public_inputs = self.user_proof.user_public_inputs();
        let user_public_inputs_targets = (0..user_public_inputs.len())
            .map(|i| {
                let len_ith_user_input = user_public_inputs[i].len();
                (0..len_ith_user_input)
                    .map(|_| circuit_builder.add_virtual_target())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let hash_user_public_inputs_targets = circuit_builder.add_virtual_hash();

        // register public inputs
        circuit_builder.register_public_inputs(&hash_user_public_inputs_targets.elements);

        let flatten_user_public_inputs_targets = user_public_inputs_targets
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let should_be_hash_user_public_inputs_targets =
            circuit_builder.hash_or_noop::<H>(flatten_user_public_inputs_targets.clone());

        circuit_builder.connect_hashes(
            should_be_hash_user_public_inputs_targets,
            hash_user_public_inputs_targets,
        );

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
                    hash_user_public_inputs_targets,
                    user_verifier_circuit_digest_targets,
                    verifier_circuit_digest_targets,
                ],
                user_verifier_data_targets,
            ),
            leaf_circuit_hash_targets,
        )
    }

    fn compile_and_build(&mut self) -> (CircuitData<F, C, D>, Self::Targets, Self::OutTargets) {
        let (circuit_builder, targets, out_targets) = self.compile();
        let circuit_data = circuit_builder.build::<C>();
        // Set up the verifier circuit digest
        self.verifier_circuit_digest = Some(circuit_data.verifier_only.circuit_digest);
        (circuit_data, targets, out_targets)
    }
}

impl<C, F, H, const D: usize> EvaluateFillCircuit<C, F, D> for LeafCircuit<C, F, H, D>
where
    C: GenericConfig<D, F = F, Hasher = H>,
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    type Value = (HashOut<F>, HashOut<F>);
    fn evaluate(&self) -> Self::Value {
        (self.user_proof.input_hash(), self.user_proof.circuit_hash())
    }

    fn fill(
        &self,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<PartialWitness<F>, anyhow::Error> {
        let (
            flatten_user_public_inputs_targets,
            [hash_user_public_inputs_targets, user_verifier_circuit_digest_targets, verifier_circuit_digest_targets],
            user_verifier_data_targets,
        ) = targets;
        let leaf_circuit_hash_targets = out_targets;

        let mut partial_witness = PartialWitness::<F>::new();
        partial_witness.set_target_arr(
            &flatten_user_public_inputs_targets,
            &self.user_proof.user_public_inputs().concat(),
        );
        partial_witness.set_hash_target(
            hash_user_public_inputs_targets,
            self.user_proof.input_hash(),
        );
        partial_witness.set_hash_target(
            user_verifier_circuit_digest_targets,
            self.user_proof.circuit_verifier_digest(),
        );
        if let Some(verifier_circuit_digest) = self.verifier_circuit_digest {
            partial_witness
                .set_hash_target(verifier_circuit_digest_targets, verifier_circuit_digest);
            let leaf_circuit_hash = PoseidonHash::hash_or_noop(
                &[
                    self.user_proof.circuit_verifier_digest().elements,
                    verifier_circuit_digest.elements,
                ]
                .concat(),
            );
            partial_witness.set_hash_target(leaf_circuit_hash_targets, leaf_circuit_hash);
        } else {
            return Err(anyhow!("Failed to generate the verifier circuit digest. Please compile the circuit once again"));
        }
        partial_witness.set_verifier_data_target(
            &user_verifier_data_targets,
            &self.user_proof.proof().circuit_data.verifier_only,
        );

        Ok(partial_witness)
    }
}

impl<C, F, H, const D: usize> Provable<F, C, D> for LeafCircuit<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    fn proof(self) -> Result<ProofData<F, C, D>, anyhow::Error> {
        let (circuit_builder, targets, out_targets) = self.compile();
        let partial_witness = self.fill(targets, out_targets)?;
        let circuit_data = circuit_builder.build::<C>();
        if circuit_data.verifier_only.circuit_digest != self.verifier_circuit_digest.unwrap() {
            return Err(anyhow!("Verifier circuit digest is not valid !"));
        }
        let proof_with_pis = circuit_data.prove(partial_witness)?;
        Ok(ProofData {
            circuit_data,
            proof_with_pis,
        })
    }
}
