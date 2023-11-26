#![allow(dead_code)]
use crate::{
    components::user_proof::UserProof, proof_data::ProofData, traits::proof::Proof, zktree::ZkTree,
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        ops::Square,
        types::{Field, Sample},
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

fn circuit_1() -> (F, ProofData<F, C, D>) {
    let mut circuit_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let mut partial_witness = PartialWitness::<F>::new();

    let a_target = circuit_builder.add_virtual_target();
    let b_target = circuit_builder.add_virtual_target();
    let c_target = circuit_builder.add_virtual_target();

    circuit_builder.register_public_input(c_target);

    let sum_target = circuit_builder.add(a_target, b_target);
    circuit_builder.connect(c_target, sum_target);

    let a = F::rand();
    let b = F::rand();
    let c = a + b;

    partial_witness.set_target(a_target, a);
    partial_witness.set_target(b_target, b);
    partial_witness.set_target(c_target, c);

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to generate proof for first circuit");

    let proof_data = ProofData {
        circuit_data,
        proof_with_pis,
    };
    (c, proof_data)
}

fn malformed_circuit_1() -> (F, ProofData<F, C, D>) {
    let mut circuit_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let mut partial_witness = PartialWitness::<F>::new();

    let a_target = circuit_builder.add_virtual_target();
    let b_target = circuit_builder.add_virtual_target();
    let c_target = circuit_builder.add_virtual_target();

    circuit_builder.register_public_input(c_target);

    let sum_target = circuit_builder.add(a_target, b_target);
    circuit_builder.connect(c_target, sum_target);

    let a = F::rand();
    let b = F::rand();
    let c = a + b + F::ONE;

    partial_witness.set_target(a_target, a);
    partial_witness.set_target(b_target, b);
    partial_witness.set_target(c_target, c);

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to generate proof for first circuit");

    let proof_data = ProofData {
        circuit_data,
        proof_with_pis,
    };
    (c, proof_data)
}

fn circuit_2() -> (F, ProofData<F, C, D>) {
    let mut circuit_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let mut partial_witness = PartialWitness::<F>::new();

    let a_target = circuit_builder.add_virtual_target();
    let b_target = circuit_builder.add_virtual_target();
    let c_target = circuit_builder.add_virtual_target();

    circuit_builder.register_public_input(c_target);

    let mul_target = circuit_builder.mul(a_target, b_target);
    circuit_builder.connect(c_target, mul_target);

    let a = F::rand();
    let b = F::rand();
    let c = a * b;

    partial_witness.set_target(a_target, a);
    partial_witness.set_target(b_target, b);
    partial_witness.set_target(c_target, c);

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to generate proof for first circuit");

    let proof_data = ProofData {
        circuit_data,
        proof_with_pis,
    };
    (c, proof_data)
}

fn circuit_3() -> (F, ProofData<F, C, D>) {
    let mut circuit_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let mut partial_witness = PartialWitness::<F>::new();

    let a_target = circuit_builder.add_virtual_target();
    let b_target = circuit_builder.add_virtual_target();
    let c_target = circuit_builder.add_virtual_target();

    circuit_builder.register_public_input(c_target);

    let a_sqr_target = circuit_builder.square(a_target);
    let b_sqr_target = circuit_builder.square(b_target);
    let out_target = circuit_builder.add(a_sqr_target, b_sqr_target);
    circuit_builder.connect(c_target, out_target);

    let a = F::rand();
    let b = F::rand();
    let c = a.square() + b.square();

    partial_witness.set_target(a_target, a);
    partial_witness.set_target(b_target, b);
    partial_witness.set_target(c_target, c);

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to generate proof for first circuit");

    let proof_data = ProofData {
        circuit_data,
        proof_with_pis,
    };
    (c, proof_data)
}

fn circuit_4() -> (F, ProofData<F, C, D>) {
    let mut circuit_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let mut partial_witness = PartialWitness::<F>::new();

    let a_target = circuit_builder.add_virtual_target();
    let b_target = circuit_builder.add_virtual_target();

    circuit_builder.register_public_input(b_target);

    let a_sqr_target = circuit_builder.square(a_target);
    circuit_builder.connect(b_target, a_sqr_target);

    let a = F::rand();
    let b = a.square();

    partial_witness.set_target(a_target, a);
    partial_witness.set_target(b_target, b);

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to generate proof for first circuit");

    let proof_data = ProofData {
        circuit_data,
        proof_with_pis,
    };
    (b, proof_data)
}

#[test]
fn test_zktree() {
    let (a1, proof_data1) = circuit_1();
    let (a2, proof_data2) = circuit_2();
    let (a3, proof_data3) = circuit_3();
    let (a4, proof_data4) = circuit_4();

    assert!(proof_data1
        .circuit_data
        .verify(proof_data1.proof_with_pis.clone())
        .is_ok());
    assert!(proof_data2
        .circuit_data
        .verify(proof_data2.proof_with_pis.clone())
        .is_ok());
    assert!(proof_data3
        .circuit_data
        .verify(proof_data3.proof_with_pis.clone())
        .is_ok());
    assert!(proof_data4
        .circuit_data
        .verify(proof_data4.proof_with_pis.clone())
        .is_ok());

    let user_proof1 = UserProof::new(
        vec![vec![a1]],
        proof_data1.circuit_data.verifier_only.circuit_digest,
        proof_data1,
    );
    let user_proof2 = UserProof::new(
        vec![vec![a2]],
        proof_data2.circuit_data.verifier_only.circuit_digest,
        proof_data2,
    );
    let user_proof3 = UserProof::new(
        vec![vec![a3]],
        proof_data3.circuit_data.verifier_only.circuit_digest,
        proof_data3,
    );
    let user_proof4 = UserProof::new(
        vec![vec![a4]],
        proof_data4.circuit_data.verifier_only.circuit_digest,
        proof_data4,
    );

    let zktree = ZkTree::new(vec![user_proof1, user_proof2, user_proof3, user_proof4])
        .expect("Failed to generate ZkTree from user proofs");

    let root = zktree.root();
    let root_proof_with_pis = &root.proof().proof_with_pis;
    assert!(root
        .proof()
        .circuit_data
        .verify(root_proof_with_pis.clone())
        .is_ok());
}

#[test]
fn test_zktree_verification() {
    let (a1, proof_data1) = circuit_1();
    let (a2, proof_data2) = circuit_2();
    let (a3, proof_data3) = circuit_3();
    let (a4, proof_data4) = circuit_4();

    let user_proof1 = UserProof::new(
        vec![vec![a1]],
        proof_data1.circuit_data.verifier_only.circuit_digest,
        proof_data1,
    );
    let user_proof2 = UserProof::new(
        vec![vec![a2]],
        proof_data2.circuit_data.verifier_only.circuit_digest,
        proof_data2,
    );
    let user_proof3 = UserProof::new(
        vec![vec![a3]],
        proof_data3.circuit_data.verifier_only.circuit_digest,
        proof_data3,
    );
    let user_proof4 = UserProof::new(
        vec![vec![a4]],
        proof_data4.circuit_data.verifier_only.circuit_digest,
        proof_data4,
    );

    let zktree = ZkTree::new(vec![user_proof1, user_proof2, user_proof3, user_proof4])
        .expect("Failed to generate ZkTree from user proofs");
    assert_eq!(zktree.get_node_proofs().len(), 3);
    zktree.verify().expect("Failed to verify zkTree");
}

// #[test]
// fn text_zktree_verification_large_proofs() {
//     let user_proofs = (0..2_i32.pow(4))
//         .map(|i| {
//             let (a, proof_data) = if i % 4 == 0 {
//                 circuit_1()
//             } else if i % 4 == 1 {
//                 circuit_2()
//             } else if i % 4 == 2 {
//                 circuit_3()
//             } else {
//                 circuit_4()
//             };

//             let user_proof = UserProof::new(
//                 vec![vec![a]],
//                 proof_data.circuit_data.verifier_only.circuit_digest,
//                 proof_data,
//             );
//             user_proof
//         })
//         .collect::<Vec<_>>();

//     let zktree = ZkTree::new(user_proofs).expect("Failed to generate ZkTree from user proofs");
//     assert!(zktree.verify().is_ok())
// }

#[test]
#[should_panic]
fn test_zktree_fails_if_user_proof_is_malformed() {
    let (a1, proof_data1) = malformed_circuit_1();
    let (a2, proof_data2) = circuit_2();
    let (a3, proof_data3) = circuit_3();
    let (a4, proof_data4) = circuit_4();

    assert!(proof_data1
        .circuit_data
        .verify(proof_data1.proof_with_pis.clone())
        .is_err());
    assert!(proof_data2
        .circuit_data
        .verify(proof_data2.proof_with_pis.clone())
        .is_ok());
    assert!(proof_data3
        .circuit_data
        .verify(proof_data3.proof_with_pis.clone())
        .is_ok());
    assert!(proof_data4
        .circuit_data
        .verify(proof_data4.proof_with_pis.clone())
        .is_ok());

    let user_proof1 = UserProof::new(
        vec![vec![a1]],
        proof_data1.circuit_data.verifier_only.circuit_digest,
        proof_data1,
    );
    let user_proof2 = UserProof::new(
        vec![vec![a2]],
        proof_data2.circuit_data.verifier_only.circuit_digest,
        proof_data2,
    );
    let user_proof3 = UserProof::new(
        vec![vec![a3]],
        proof_data3.circuit_data.verifier_only.circuit_digest,
        proof_data3,
    );
    let user_proof4 = UserProof::new(
        vec![vec![a4]],
        proof_data4.circuit_data.verifier_only.circuit_digest,
        proof_data4,
    );

    let zktree = ZkTree::new(vec![user_proof1, user_proof2, user_proof3, user_proof4])
        .expect("Failed to generate ZkTree from user proofs");

    let root = zktree.root();
    let root_proof_with_pis = &root.proof().proof_with_pis;
    assert!(root
        .proof()
        .circuit_data
        .verify(root_proof_with_pis.clone())
        .is_err());
}
