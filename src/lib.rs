use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{Field, One, ToBytes, UniformRand};
use rand_core::RngCore;
use std::vec;
use chacha20::{ChaCha20, Key, Nonce};
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};

use bls_crypto::hash_to_curve::HashToCurve;
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

/// Computes the ROM-heuristic hash `H(U, V, additional data) -> G2`, 
/// used to construct the authentication tag for the ciphertext.
fn construct_tag_hash<G: AffineCurve, E: PairingEngine, H: HashToCurve<Output=E::G2Affine>>(
    u: G, stream_ciphertext: &[u8], additional_data: &[u8]) -> E::G2Affine
{
    // Encode the data to be hashed as U || V || additional data
    // TODO: Length prefix V
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);
    hash_input.extend_from_slice(additional_data);

    let hasher = H::new().unwrap();
    let domain = &b"auth_tag"[..];
    let tag_hash = hasher.hash(domain, &hash_input).unwrap();
    tag_hash
}

impl<E: PairingEngine> EncryptionPubkey<E> { 
    pub fn encrypt_msg<R: RngCore, H: HashToCurve<Output=E::G2Affine>>
        (&self, msg: &[u8], additional_data: &[u8], rng: &mut R) -> Ciphertext<E>
    {
        // TODO: Come back and rename these
        let g1_generator = E::G1Affine::prime_subgroup_generator();
        let r = Fr::<E>::rand(rng);
        let u = g1_generator.mul(r).into();

        // Create the stream cipher key, which is r * Y
        // where r is the random nonce, and Y is the threshold pubkey that you are encrypting to.
        let stream_cipher_key_curve_elem = self.key.mul(r).into();
        // Convert this to stream cipher element into a key for the stream cipher
        // TODO: Use stream cipher Trait
        let mut prf_key = Vec::new();
        stream_cipher_key_curve_elem.write(&mut prf_key).unwrap();
        let nonce = Nonce::from_slice(b"secret nonce");
        let mut cipher = ChaCha20::new(Key::from_slice(&prf_key), nonce);

        // Encrypt the message
        let mut stream_ciphertext = msg.to_vec();
        cipher.apply_keystream(&mut stream_ciphertext);

        // Create the authentication tag
        // The authentication tag is r H(U, stream_ciphertext, additional_data)
        // So first we compute the tag hash, and then scale it by r to get the auth tag.
        let tag_hash = construct_tag_hash::<_, E, H>(u, msg, additional_data);
        let auth_tag = tag_hash.mul(r).into();

        Ciphertext::<E>{nonce: u, ciphertext: stream_ciphertext, auth_tag}
    }
}

impl<E: PairingEngine> Ciphertext<E> 
{
    // TODO: Change this output to an enum
    /// Check that the provided ciphertext is validly constructed, and therefore is decryptable.
    pub fn check_ciphertext_validity<H: HashToCurve<Output=E::G2Affine>>(
        &self, additional_data: &[u8]) -> bool 
    {
        // The authentication tag is valid iff e(nonce, tag hash) = e(g, auth tag)
        // Notice that this is equivalent to checking the following:
        // `e(nonce, tag hash) * e(g, auth tag)^{-1} = 1`
        // `e(nonce, tag hash) * e(-g, auth tag) = 1`
        // So first we construct the tag hash, and then we check whether this property holds or not.
        let tag_hash = construct_tag_hash::<_, E, H>(self.nonce, &self.ciphertext, additional_data);
        let g_inv = -E::G1Affine::prime_subgroup_generator();
        let pairing_prod_result = E::product_of_pairings(&[
            (self.nonce.into(), tag_hash.into()),
            (g_inv.into(), self.auth_tag.into()),
        ]);

        // Check that the result equals one
        pairing_prod_result == E::Fqk::one()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
