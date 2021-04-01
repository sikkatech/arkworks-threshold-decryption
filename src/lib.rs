#![allow(type_alias_bounds)]
// use ark_ec::{AffineCurve as ark_AffineCurve, PairingEngine as ark_PairingEngine};
use ark_serialize::CanonicalSerialize;
use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{One, ToBytes, UniformRand};
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use rand_core::RngCore;
use std::vec;


// use bls_crypto::hash_to_curve::HashToCurve;

use log::error;
use thiserror::Error;

// use algebra::{PairingEngine, AffineCurve};

mod hash_to_curve;
pub mod key_generation;

type G1<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G1Affine;
type G2<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G2Affine;
type Fr<P: ThresholdEncryptionParameters> =  <<P::E as PairingEngine>::G1Affine as AffineCurve>::ScalarField;
// type Fqk<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::Fqk;
// type Fr<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::Fr;

// use ark_serialize::CanonicalDeserialize;


// trait HashToCurve : Sized {
//     // fn new() -> Self;
//     fn hash(
//         &self,
//         domain: &[u8],
//         message: &[u8],
//     ) -> ark_bls12_381::G2Affine;
// }

// struct Hasher;
// impl HashToCurve for Hasher {
//     fn hash(
//         &self,
//         domain: &[u8],
//         message: &[u8],
//     ) -> ark_bls12_381::G2Affine
//     {
//         let mut expected_compressed = [0u8; 96];
//         let expected_hex_string = "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903";
//         hex::decode_to_slice(expected_hex_string, &mut expected_compressed).expect("Failed to decode hex");
//         let expected = <ark_bls12_381::G2Affine as CanonicalDeserialize>::deserialize(&expected_compressed[..]).unwrap();
//         expected
//     }
// }

pub fn mock_hash<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    // let mut expected_compressed = [0u8; 96];
    // let expected_hex_string = "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903";
    // hex::decode_to_slice(expected_hex_string, &mut expected_compressed)
    //     .expect("Failed to decode hex");
    // let expected = <T as CanonicalDeserialize>::deserialize(&expected_compressed[..]).unwrap();
    // expected

    let point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(point_ser.clone()).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
    // type H: HashToCurve<Output= G2<Self>>;
}

pub struct EncryptionPubkey<P: ThresholdEncryptionParameters> {
    pub key: G2<P>,
}

pub struct ShareVerificationPubkey<P: ThresholdEncryptionParameters> {
    pub decryptor_pubkeys: Vec<G2<P>>,
}

pub struct PrivkeyShare<P: ThresholdEncryptionParameters> {
    pub index: usize,
    pub privkey: Fr<P>,
    pub pubkey: G2<P>,
}

pub struct Ciphertext<P: ThresholdEncryptionParameters> {
    pub nonce: G1<P>, // U
    pub ciphertext: Vec<u8>, // V
    pub auth_tag: G2<P>, // W
}

pub struct DecryptionShare<P: ThresholdEncryptionParameters> {
    pub decryptor_index: usize, // i
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

    // let hasher = P::H::new().unwrap();
    // let domain = &b"auth_tag"[..];
    // let tag_hash = hasher.hash(domain, &hash_input).unwrap();
    // let tag_hash = mock_hash::<G2<P>>(/*&hash_input*/);
    let tag_hash = mock_hash(&hash_input);
    tag_hash
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

        // This nonce doesn't matter, as we never have key re-use.
        // We keep it fixed to minimize the data transmitted.
        let chacha_nonce = Nonce::from_slice(b"secret nonce");
        let mut cipher = ChaCha20::new(Key::from_slice(&prf_key), chacha_nonce);

        // Encrypt the message
        let mut stream_ciphertext = msg.to_vec();
        cipher.apply_keystream(&mut stream_ciphertext);

        // Create the authentication tag
        // The authentication tag is r H(U, stream_ciphertext, additional_data)
        // So first we compute the tag hash, and then scale it by r to get the auth tag.
        let tag_hash = construct_tag_hash::<P>(u, msg, additional_data);
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
        let tag_hash = construct_tag_hash::<P>(self.nonce, &self.ciphertext, additional_data);
        let g_inv = -G1::<P>::prime_subgroup_generator();
        let pairing_prod_result = P::E::product_of_pairings(&[
            (self.nonce.into(), tag_hash.into()),
            (g_inv.into(), self.auth_tag.into()),
        ]);

        // Check that the result equals one
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
        c: Ciphertext<P>,
        additional_data: &[u8],
        vpk: ShareVerificationPubkey<P>,
    ) -> bool 
    {
        let res = c.check_ciphertext_validity(additional_data);
        if res == false {
            return false;
        }

        let g2_inv = -G2::<P>::prime_subgroup_generator();
        let pairing_prod_result = P::E::product_of_pairings(&[
            (
                self.decryption_share.into(),
                g2_inv.into(),
            ),
            (
                c.nonce.into(),
                vpk.decryptor_pubkeys[self.decryptor_index].into(),
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

    // let stream_cipher_key_curve_elem = ;/*Lagrange on shares here*/
    // let mut prf_key = Vec::new();
    // stream_cipher_key_curve_elem.write(&mut prf_key).unwrap();

    // let chacha_nonce = Nonce::from_slice(b"secret nonce");
    // let mut cipher = ChaCha20::new(Key::from_slice(&prf_key), chacha_nonce);

    // cipher.apply_keystream(&mut c.ciphertext);

    Ok(())
}


#[cfg(test)]
mod tests {

    use crate::key_generation::*;
    use crate::*;
    use ark_std::test_rng;

    // use algebra::curves::bls12::Bls12Parameters;// as algebra_bls12_params;
    // use ark_ec::bls12::Bls12Parameters;

    pub struct TestingParameters {}

    impl ThresholdEncryptionParameters for TestingParameters {
        type E = ark_bls12_381::Bls12_381;
        // type E = Bls12_377;
        // type H = bls_crypto::hash_to_curve::try_and_increment::TryAndIncrement::<bls_crypto::hashers::DirectHasher,
        // <ark_bls12_381::Parameters as Bls12Parameters>::G2Parameters
        // <algebra_bls12_params as Bls12Parameters>::G2Parameters
        // <Parameters as Bls12Parameters>::G2Parameters,
        // type H = Hasher;
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
        for i in 0..=num_keys {
            dec_shares.push(privkeys[i].create_share(&ciphertext, ad).unwrap());
        }
        assert!(dec_shares[0].verify_share(ciphertext, ad, svp));
    }
}
