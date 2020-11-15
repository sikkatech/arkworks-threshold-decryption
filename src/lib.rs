use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand, Zero};
use rand_core::RngCore;

pub mod key_generation;

type Fr<E: PairingEngine> = <E::G1Affine as AffineCurve>::ScalarField;

pub struct EncryptionPubkey<E: PairingEngine> {
    pub key : E::G1Affine,
}

pub struct ShareVerificationPubkey<E: PairingEngine> {
    pub decryptor_pubkeys : Vec<E::G1Affine>,
}

pub struct PrivkeyShare<E: PairingEngine> {
    pub index : usize,
    pub privkey : Fr<E>,
    pub pubkey : E::G1Affine,
}

pub struct Ciphertext<E: PairingEngine> {
    pub nonce: E::G1Affine,
    pub ciphertext: Vec<u8>,
    pub auth_tag: E::G2Affine,
}

impl<E: PairingEngine> EncryptionPubkey<E> { 
    pub fn encrypt_msg<R: RngCore>(&self, msg: &[u8], additional_data: &[u8], rng: &mut R) -> Ciphertext<E>
    {
        // TODO: Come back and rename these
        let g1_generator = E::G1Affine::prime_subgroup_generator();
        let r = Fr::<E>::rand(rng);
        let U = g1_generator.mul(r).into();
        let prf_seed = self.key.mul(r).into();
        // TODO: PRF Trait

        // TODO: Instead get this from the hash
        let tag_hash = E::G2Affine::prime_subgroup_generator();
        let auth_tag = tag_hash.mul(r).into();
        // Just to compile
        Ciphertext::<E>{nonce: U, ciphertext: msg.to_vec(), auth_tag}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
