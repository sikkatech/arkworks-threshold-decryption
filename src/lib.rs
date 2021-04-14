#![allow(type_alias_bounds)]
use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{One, ToBytes, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use rand_core::RngCore;
use std::vec;

use log::error;
use thiserror::Error;

use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;

mod hash_to_curve;
pub mod key_generation;

type G1<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G1Affine;
type G2<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G2Affine;
type Fr<P: ThresholdEncryptionParameters> =
    <<P::E as PairingEngine>::G1Affine as AffineCurve>::ScalarField;

pub fn mock_hash<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}

pub struct EncryptionPubkey<P: ThresholdEncryptionParameters> {
    pub key: G1<P>, // Y=Y_0=x_0*P_1
}

pub struct ShareVerificationPubkey<P: ThresholdEncryptionParameters> {
    pub decryptor_pubkeys: Vec<G1<P>>, // (Y_1 .. Y_n)
}

pub struct PrivkeyShare<P: ThresholdEncryptionParameters> {
    pub index: usize,   // i
    pub privkey: Fr<P>, // x_i
    pub pubkey: G1<P>,  // Y_i
}

pub struct Ciphertext<P: ThresholdEncryptionParameters> {
    pub nonce: G1<P>,        // U
    pub ciphertext: Vec<u8>, // V
    pub auth_tag: G2<P>,     // W
}

pub struct DecryptionShare<P: ThresholdEncryptionParameters> {
    pub decryptor_index: usize,  // i
    pub decryption_share: G1<P>, // U_i = x_i*U
}

#[derive(Debug, Error)]
/// Error type
pub enum ThresholdEncryptionError {
    /// Error
    #[error("ciphertext verification failed")]
    CiphertextVerificationFailed,

    /// Error
    #[error("Decryption share verification failed")]
    DecryptionShareVerificationFailed,

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,
    // Serialization error in Zexe
    // #[error(transparent)]
    // SerializationError(#[from] algebra::SerializationError),
}

/// Computes the ROM-heuristic hash `H(U, V, additional data) -> G2`,
/// used to construct the authentication tag for the ciphertext.
fn construct_tag_hash<P: ThresholdEncryptionParameters>(
    u: G1<P>,
    stream_ciphertext: &[u8],
    additional_data: &[u8],
) -> G2<P> {
    // Encode the data to be hashed as U || V || additional data
    // TODO: Length prefix V
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);
    hash_input.extend_from_slice(additional_data);

    mock_hash(&hash_input)
}

impl<P: ThresholdEncryptionParameters> EncryptionPubkey<P> {
    pub fn encrypt_msg<R: RngCore>(
        &self,
        msg: &[u8],
        additional_data: &[u8],
        rng: &mut R,
    ) -> Ciphertext<P> {
        // TODO: Come back and rename these
        let g1_generator = G1::<P>::prime_subgroup_generator();
        let r = Fr::<P>::rand(rng);
        let u = g1_generator.mul(r).into();

        // Create the stream cipher key, which is r * Y
        // where r is the random nonce, and Y is the threshold pubkey that you are encrypting to.
        let stream_cipher_key_curve_elem = self.key.mul(r).into();

        // Convert this to stream cipher element into a key for the stream cipher
        // TODO: Use stream cipher Trait
        let mut prf_key = Vec::new();
        stream_cipher_key_curve_elem.write(&mut prf_key).unwrap();
        let mut hasher = VarBlake2b::new(32).unwrap();
        hasher.update(prf_key);
        let mut prf_key_32 = [0u8; 32];
        hasher.finalize_variable(|p| prf_key_32.clone_from_slice(p));

        // This nonce doesn't matter, as we never have key re-use.
        // We keep it fixed to minimize the data transmitted.
        let chacha_nonce = Nonce::from_slice(b"secret nonce");
        let mut cipher = ChaCha20::new(Key::from_slice(&prf_key_32), chacha_nonce);

        // Encrypt the message
        let mut stream_ciphertext = msg.to_vec();
        cipher.apply_keystream(&mut stream_ciphertext);

        // Create the authentication tag
        // The authentication tag is r H(U, stream_ciphertext, additional_data)
        // So first we compute the tag hash, and then scale it by r to get the auth tag.
        let tag_hash = construct_tag_hash::<P>(u, &stream_ciphertext[..], additional_data);
        let auth_tag = tag_hash.mul(r).into();

        Ciphertext::<P> {
            nonce: u,
            ciphertext: stream_ciphertext,
            auth_tag,
        }
    }
}

impl<P: ThresholdEncryptionParameters> Ciphertext<P> {
    // TODO: Change this output to an enum
    /// Check that the provided ciphertext is validly constructed, and therefore is decryptable.
    pub fn check_ciphertext_validity(&self, additional_data: &[u8]) -> bool {
        // The authentication tag is valid iff e(nonce, tag hash) = e(g, auth tag)
        // Notice that this is equivalent to checking the following:
        // `e(nonce, tag hash) * e(g, auth tag)^{-1} = 1`
        // `e(nonce, tag hash) * e(-g, auth tag) = 1`
        // So first we construct the tag hash, and then we check whether this property holds or not.

        let tag_hash = construct_tag_hash::<P>(self.nonce, &self.ciphertext[..], additional_data);
        let g_inv = -G1::<P>::prime_subgroup_generator();

        let pairing_prod_result = P::E::product_of_pairings(&[
            (self.nonce.into(), tag_hash.into()),
            (g_inv.into(), self.auth_tag.into()),
        ]);

        pairing_prod_result
            == <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::one()
    }
}

// TODO: Learn how rust crypto libraries handle private keys
impl<P: ThresholdEncryptionParameters> PrivkeyShare<P> {
    pub fn create_share(
        &self,
        c: &Ciphertext<P>,
        additional_data: &[u8],
    ) -> Result<DecryptionShare<P>, ThresholdEncryptionError> {
        let res = c.check_ciphertext_validity(additional_data);
        if res == false {
            return Err(ThresholdEncryptionError::CiphertextVerificationFailed);
        }
        let decryption_share = c.nonce.mul(self.privkey).into();
        Ok(DecryptionShare {
            decryptor_index: self.index,
            decryption_share,
        })
    }
}

impl<P: ThresholdEncryptionParameters> DecryptionShare<P> {
    pub fn verify_share(
        &self,
        c: &Ciphertext<P>,
        additional_data: &[u8],
        vpk: &ShareVerificationPubkey<P>,
    ) -> bool {
        let res = c.check_ciphertext_validity(additional_data);
        if res == false {
            return false;
        }

        // e(Ui,H) ?= e(Yi,W) => e(-Ui,H)*e(Yi,W) ?= 1
        let tag_hash = construct_tag_hash::<P>(c.nonce, &c.ciphertext[..], additional_data);
        let pairing_prod_result = P::E::product_of_pairings(&[
            ((-self.decryption_share).into(), tag_hash.into()),
            (
                vpk.decryptor_pubkeys[self.decryptor_index - 1].into(),
                c.auth_tag.into(),
            ),
        ]);
        pairing_prod_result
            == <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::one()
    }
}

pub fn share_combine<P: ThresholdEncryptionParameters>(
    plaintext: &mut [u8],
    c: Ciphertext<P>,
    additional_data: &[u8],
    shares: Vec<DecryptionShare<P>>,
) -> Result<(), ThresholdEncryptionError> {
    let res = c.check_ciphertext_validity(additional_data);
    if res == false {
        return Err(ThresholdEncryptionError::CiphertextVerificationFailed);
    }

    let mut stream_cipher_key_curve_elem: G1<P> = G1::<P>::zero();
    for j in 1..=shares.len() {
        let mut lagrange_coeff: Fr<P> = Fr::<P>::one();
        let ji = <Fr<P> as From<u64>>::from(j as u64);
        for i in 1..=shares.len() {
            if i != j {
                let ii = <Fr<P> as From<u64>>::from(i as u64);
                lagrange_coeff = lagrange_coeff * ((Fr::<P>::zero() - (ii)) / (ji - ii));
            }
        }

        stream_cipher_key_curve_elem = stream_cipher_key_curve_elem
            + shares[j - 1].decryption_share.mul(lagrange_coeff).into();
    }

    // Calculate the chacha20 key
    let mut prf_key = Vec::new();
    stream_cipher_key_curve_elem.write(&mut prf_key).unwrap();
    let mut hasher = VarBlake2b::new(32).unwrap();
    hasher.update(prf_key);
    let mut prf_key_32 = [0u8; 32];
    hasher.finalize_variable(|p| prf_key_32.clone_from_slice(p));

    // This nonce doesn't matter, as we never have key re-use.
    // We keep it fixed to minimize the data transmitted.
    let chacha_nonce = Nonce::from_slice(b"secret nonce");
    let mut cipher = ChaCha20::new(Key::from_slice(&prf_key_32), chacha_nonce);

    plaintext.clone_from_slice(&c.ciphertext[..]);
    cipher.apply_keystream(plaintext);

    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::key_generation::*;
    use crate::*;
    use ark_std::test_rng;

    pub struct TestingParameters {}

    impl ThresholdEncryptionParameters for TestingParameters {
        type E = ark_bls12_381::Bls12_381;
    }

    #[test]
    fn completeness_test() {
        let mut rng = test_rng();
        let threshold = 3;
        let num_keys = 5;
        let (epk, svp, privkeys) = generate_keys::<TestingParameters, ark_std::rand::rngs::StdRng>(
            threshold, num_keys, &mut rng,
        );

        let msg: &[u8] = "abc".as_bytes();
        let ad: &[u8] = "".as_bytes();

        let ciphertext = epk.encrypt_msg(msg, ad, &mut rng);

        let mut dec_shares: Vec<DecryptionShare<TestingParameters>> = Vec::new();
        for i in 0..num_keys {
            dec_shares.push(privkeys[i].create_share(&ciphertext, ad).unwrap());
            assert!(dec_shares[i].verify_share(&ciphertext, ad, &svp));
        }

        let mut plaintext: Vec<u8> = ciphertext.ciphertext.clone();
        share_combine(&mut plaintext, ciphertext, ad, dec_shares).unwrap();
        assert!(plaintext == msg)
    }
}
