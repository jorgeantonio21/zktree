use anyhow::Error;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::components::{leaf_proof::LeafProof, node_proof::NodeProof};

pub(crate) fn generate_node_proofs_from_leaves<C, F, H, const D: usize>(
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

pub(crate) fn generate_node_proofs_from_nodes<C, F, H, const D: usize>(
    node_proofs: &Vec<NodeProof<C, F, H, D>>,
    start_child_index: usize,
    node_proofs_len: usize,
) -> Result<Vec<NodeProof<C, F, H, D>>, Error>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F> + Send + Sync,
{
    (start_child_index..node_proofs_len)
        .into_par_iter()
        .step_by(2)
        .map(|i| NodeProof::new_from_children(&node_proofs[i], &node_proofs[i + 1]))
        .collect::<Result<Vec<_>, _>>()
}
