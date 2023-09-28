use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};
use zktree::proof_components::user_proof::UserProof;

pub struct ZkTreeService<C, F, const D: usize>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    user_proofs: Vec<UserProof<C, F, D>>,
}

impl<C, F, const D: usize> ZkTreeService<C, F, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    pub fn publish_proof(&mut self, user_proof: UserProof<C, F, D>) {
        self.user_proofs.push(user_proof);
    }
}
