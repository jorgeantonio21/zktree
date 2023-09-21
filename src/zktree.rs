use std::marker::PhantomData;

use anyhow::{anyhow, Error};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    proof_components::{leaf_proof::LeafProof, node_proof::NodeProof, user_proof::UserProof},
    traits::proof::Proof,
};

pub struct ZkTree<C, F, H, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    user_proofs: Vec<UserProof<C, F, D>>,
    intermediate_proofs: Vec<Box<dyn Proof<C, F, D>>>,
    root_proof: Box<dyn Proof<C, F, D>>,
    _phantom_data: PhantomData<H>,
}

impl<C, F, H, const D: usize> ZkTree<C, F, H, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F, Hasher = H>,
    H: AlgebraicHasher<F>,
{
    pub fn new(user_proofs: Vec<UserProof<C, F, D>>) -> Result<Self, Error> {
        debug_assert!(user_proofs.len().is_power_of_two() && user_proofs.len() > 1);
        let zktree_height = user_proofs.len().ilog2();

        let mut intermediate_proofs: Vec<Box<dyn Proof<C, F, D>>> = vec![];
        for user_proof in &user_proofs {
            intermediate_proofs.push(Box::new(LeafProof::new_from_user_proof(user_proof)?));
        }

        let mut current_tree_height_index = 0;
        let mut current_child_index = 0;
        let mut index = 0;

        for height in 0..zktree_height {
            let chunk_size = 1 << (zktree_height - height);

            let thread_proofs = (current_child_index..current_child_index + chunk_size)
                .into_par_iter()
                .step_by(2)
                .for_each(|i| {
                    let node_proof = NodeProof::new_from_children(
                        intermediate_proofs[i].as_ref(),
                        intermediate_proofs[i + 1].as_ref(),
                    );
                    if let Ok(proof) = node_proof {
                        intermediate_proofs.push(Box::new(proof));
                    }
                });
            if intermediate_proofs.len() != current_child_index + chunk_size {
                return Err(anyhow!("Proof generation failed at height {}", height));
            }
            current_child_index += chunk_size
        }

        let root_proof = intermediate_proofs.last().unwrap().clone(); // unwrap never panics, it follows from assumption that user_proofs.len() > 1

        Ok(Self {
            user_proofs,
            intermediate_proofs,
            root_proof,
            _phantom_data: PhantomData,
        })
    }
}
