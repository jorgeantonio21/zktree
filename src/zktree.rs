use std::marker::PhantomData;

use anyhow::{anyhow, Error};
use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, merkle_tree::MerkleTree},
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::{
    proof_components::{leaf_proof::LeafProof, node_proof::NodeProof, user_proof::UserProof},
    traits::proof::Proof,
    utils::{generate_node_proofs_from_leaves, generate_node_proofs_from_nodes},
};

pub struct ZkTree<C, F, H, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    user_proofs: Vec<UserProof<C, F, D>>,
    leaf_proofs: Vec<LeafProof<C, F, H, D>>,
    node_proofs: Vec<NodeProof<C, F, H, D>>,
    _phantom_data: PhantomData<H>,
}

impl<C, F, H, const D: usize> ZkTree<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F> + Send + Sync,
{
    pub fn new(user_proofs: Vec<UserProof<C, F, D>>) -> Result<Self, Error> {
        debug_assert!(user_proofs.len().is_power_of_two() && user_proofs.len() > 1);
        let zktree_height = user_proofs.len().ilog2();

        let mut leaf_proofs: Vec<LeafProof<C, F, H, D>> = Vec::with_capacity(user_proofs.len());
        for user_proof in &user_proofs {
            leaf_proofs.push(LeafProof::new_from_user_proof(user_proof)?);
        }

        let mut node_proofs = Vec::with_capacity((1 << (zktree_height + 1)) - 1);
        let mut start_child_index = 0;
        let mut node_proofs_len = 0;

        for height in 0..zktree_height {
            if height == 0 {
                node_proofs.extend(generate_node_proofs_from_leaves(&leaf_proofs)?);
                node_proofs_len = node_proofs.len();
            } else {
                node_proofs.extend(generate_node_proofs_from_nodes(
                    &node_proofs,
                    start_child_index,
                    node_proofs_len,
                )?);
                start_child_index = node_proofs_len;
                node_proofs_len += 1 << (zktree_height - height - 1);
            }
        }

        Ok(Self {
            user_proofs,
            leaf_proofs,
            node_proofs,
            _phantom_data: PhantomData,
        })
    }
}

impl<C, F, H, const D: usize> ZkTree<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    pub fn root(&self) -> &NodeProof<C, F, H, D> {
        self.node_proofs.last().expect("Failed to retrieve root")
    }

    pub fn get_user_proofs(&self) -> Vec<&UserProof<C, F, D>> {
        self.user_proofs.iter().collect::<Vec<_>>()
    }

    pub fn get_leaf_proofs(&self) -> Vec<&LeafProof<C, F, H, D>> {
        self.leaf_proofs.iter().collect::<Vec<_>>()
    }

    pub fn get_node_proofs(&self) -> Vec<&NodeProof<C, F, H, D>> {
        self.node_proofs.iter().collect::<Vec<_>>()
    }
}

impl<C, F, H, const D: usize> ZkTree<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    pub fn verify(&self) -> Result<(), Error> {
        let root = self.root();
        let root_proof_with_pis = root.proof().proof_with_pis.clone();
        root.proof().circuit_data.verify(root_proof_with_pis)?;
        let input_tree_leaves = self
            .user_proofs
            .iter()
            .map(|user_proof| user_proof.user_public_inputs().concat())
            .collect::<Vec<_>>();
        let input_hashes_merkle_tree = MerkleTree::<F, H>::new(input_tree_leaves, 0);
        if input_hashes_merkle_tree.cap.0[0] != root.input_hash() {
            return Err(anyhow!("Input hashes do not match"));
        }
        Ok(())
    }
}
