use std::marker::PhantomData;

use anyhow::{anyhow, Error};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::proof_components::{
    leaf_proof::LeafProof, node_proof::NodeProof, user_proof::UserProof,
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
        let mut current_child_index = 0;

        for height in 0..zktree_height {
            let chunk_size = 1 << (zktree_height - height);

            if height == 0 {
                node_proofs.extend(generate_node_proofs_from_leaves(&leaf_proofs)?);
            } else {
                node_proofs.extend(generate_node_proofs_from_nodes(
                    &node_proofs,
                    current_child_index,
                    chunk_size,
                )?);
            }
            if node_proofs.len() != (current_child_index + chunk_size) as usize {
                return Err(anyhow!("Proof generation failed at height {}", height));
            }
            current_child_index += chunk_size
        }

        Ok(Self {
            user_proofs,
            leaf_proofs,
            node_proofs: node_proofs,
            _phantom_data: PhantomData,
        })
    }
}

fn generate_node_proofs_from_leaves<C, F, H, const D: usize>(
    leaf_proofs: &Vec<LeafProof<C, F, H, D>>,
) -> Result<Vec<NodeProof<C, F, H, D>>, Error>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F> + Send + Sync,
{
    (0..leaf_proofs.len())
        .into_par_iter()
        .step_by(2)
        .map(|i| NodeProof::new_from_children(&leaf_proofs[i], &leaf_proofs[i + 1]))
        .collect::<Result<Vec<_>, _>>()
}

fn generate_node_proofs_from_nodes<C, F, H, const D: usize>(
    node_proofs: &Vec<NodeProof<C, F, H, D>>,
    current_child_index: i32,
    chunk_size: i32,
) -> Result<Vec<NodeProof<C, F, H, D>>, Error>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F> + Send + Sync,
{
    ((current_child_index as usize)..((current_child_index + chunk_size) as usize))
        .into_par_iter()
        .step_by(2)
        .map(|i| NodeProof::new_from_children(&node_proofs[i], &node_proofs[i + 1]))
        .collect::<Result<Vec<_>, _>>()
}
