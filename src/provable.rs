use crate::circuit_compiler::ProofData;
use anyhow::Error;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};

pub trait Provable<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
where
    Self: Sized,
{
    fn proof(self) -> Result<ProofData<F, C, D>, Error>;
    fn prove_and_verify(self) -> Result<(), Error> {
        let proof_data = self.proof()?;
        proof_data.circuit_data.verify(proof_data.proof_with_pis)
    }
}
