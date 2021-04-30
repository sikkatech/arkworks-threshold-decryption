#![allow(type_alias_bounds)]
use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{One, ToBytes, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::vec;
use zeroize::Zeroize;

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

const PLAINTEXT_VALIDITY_HASH_SIZE: usize = 32;

pub mod ark_serde {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde_bytes::{Deserialize, Serialize};

    pub fn serialize<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: CanonicalSerialize,
    {
        use serde::ser::Error;
        let mut bytes = vec![];
        data.serialize(&mut bytes).map_err(S::Error::custom)?;
        serde_bytes::Bytes::new(&bytes).serialize(serializer)
    }
    pub fn deserialize<'d, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'d>,
        T: CanonicalDeserialize,
    {
        use serde::de::Error;
        let bytes = <serde_bytes::ByteBuf>::deserialize(deserializer)?;
        T::deserialize(bytes.as_slice()).map_err(D::Error::custom)
    }
}

pub fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptionPubkey<P: ThresholdEncryptionParameters> {
    #[serde(with = "ark_serde")]
    pub key: G1<P>, // Y=Y_0=x_0*P_1
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareVerificationPubkey<P: ThresholdEncryptionParameters> {
    #[serde(with = "ark_serde")]
    pub decryptor_pubkeys: Vec<G1<P>>, // (Y_1 .. Y_n)
}

#[derive(Serialize, Deserialize, Clone, Zeroize, Debug)]
pub struct PrivkeyShare<P: ThresholdEncryptionParameters> {
    pub index: usize, // i
    #[serde(with = "ark_serde")]
    #[zeroize(drop)]
    pub privkey: Fr<P>, // x_i
    #[serde(with = "ark_serde")]
    pub pubkey: G1<P>, // Y_i
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Ciphertext<P: ThresholdEncryptionParameters> {
    #[serde(with = "ark_serde")]
    pub nonce: G1<P>, // U
    pub ciphertext: Vec<u8>, // V
    #[serde(with = "ark_serde")]
    pub auth_tag: G2<P>, // W
}

#[derive(Serialize, Deserialize, Clone ,Debug)]
pub struct DecryptionShare<P: ThresholdEncryptionParameters> {
    pub decryptor_index: usize, // i
    #[serde(with = "ark_serde")]
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

    #[error("plaintext verification failed")]
    PlaintextVerificationFailed,
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

    hash_to_g2(&hash_input)
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

        // Calculate message hash needed for post-decryption plaintext validation
        let mut hasher = VarBlake2b::new(PLAINTEXT_VALIDITY_HASH_SIZE).unwrap();
        let mut msg_digest = [0u8; PLAINTEXT_VALIDITY_HASH_SIZE];
        hasher.update(msg);
        hasher.finalize_variable(|p| msg_digest.clone_from_slice(p));

        // Encrypt the message
        let mut stream_ciphertext = msg_digest
            .to_vec()
            .into_iter()
            .chain(msg.to_vec().into_iter())
            .collect::<Vec<u8>>();
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
    pub fn check_decryption_share_validity(
        &self,
        c: &Ciphertext<P>,
        vpk: &ShareVerificationPubkey<P>,
        additional_data: &[u8],
    ) -> bool {
        // We use the fact that e(Ui,H) ?= e(Yi,W) => e(-Ui,H)*e(Yi,W) ?= 1
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

        self.check_decryption_share_validity(c, vpk, additional_data)
    }
}

fn plaintext_validity_check(plaintext: &mut [u8]) -> Result<&mut [u8], ThresholdEncryptionError> {
    if plaintext.len() < PLAINTEXT_VALIDITY_HASH_SIZE {
        return Err(ThresholdEncryptionError::PlaintextVerificationFailed);
    }

    let msg_digest_in = &plaintext.to_vec()[0..PLAINTEXT_VALIDITY_HASH_SIZE];
    let mut msg_digest_calc = [0u8; PLAINTEXT_VALIDITY_HASH_SIZE];

    let mut hasher = VarBlake2b::new(PLAINTEXT_VALIDITY_HASH_SIZE).unwrap();
    let msg = &plaintext.to_vec()[32..];
    hasher.update(msg);
    hasher.finalize_variable(|p| msg_digest_calc.clone_from_slice(p));

    if msg_digest_calc != msg_digest_in {
        return Err(ThresholdEncryptionError::PlaintextVerificationFailed);
    }
    // Strip off digest from message
    Ok(&mut plaintext[PLAINTEXT_VALIDITY_HASH_SIZE..])
}

fn share_combine_no_check<'a, P: ThresholdEncryptionParameters>(
    c: &Ciphertext<P>,
    shares: &Vec<DecryptionShare<P>>,
) -> Result<Vec<u8>, ThresholdEncryptionError> {
    let mut stream_cipher_key_curve_elem: G1<P> = G1::<P>::zero();
    for j in shares.iter() {
        let mut lagrange_coeff: Fr<P> = Fr::<P>::one();
        let ji = <Fr<P> as From<u64>>::from(j.decryptor_index as u64);
        for i in shares.iter() {
            let ii = <Fr<P> as From<u64>>::from(i.decryptor_index as u64);
            if ii != ji {
                lagrange_coeff = lagrange_coeff * ((Fr::<P>::zero() - (ii)) / (ji - ii));
            }
        }

        stream_cipher_key_curve_elem =
            stream_cipher_key_curve_elem + j.decryption_share.mul(lagrange_coeff).into();
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

    let mut plaintext = Vec::with_capacity(c.ciphertext.len());
    for _ in 0..c.ciphertext.len() {
        plaintext.push(Default::default());
    }

    plaintext.clone_from_slice(&c.ciphertext[..]);
    cipher.apply_keystream(&mut plaintext);
    plaintext = plaintext_validity_check(&mut plaintext).unwrap().to_vec();

    Ok(plaintext)
}

pub fn share_combine<'a, P: ThresholdEncryptionParameters>(
    c: Ciphertext<P>,
    additional_data: &[u8],
    shares: Vec<DecryptionShare<P>>,
) -> Result<Vec<u8>, ThresholdEncryptionError> {
    let res = c.check_ciphertext_validity(additional_data);
    if res == false {
        return Err(ThresholdEncryptionError::CiphertextVerificationFailed);
    }

    let plaintext = share_combine_no_check(&c, &shares).unwrap();

    Ok(plaintext.to_vec())
}

pub fn batch_share_combine<'a, P: ThresholdEncryptionParameters>(
    ciphertexts: Vec<Ciphertext<P>>,
    additional_data: Vec<&[u8]>,
    shares: Vec<Vec<DecryptionShare<P>>>,
) -> Result<Vec<Vec<u8>>, ThresholdEncryptionError> {
    // We first check for ciphertext validity across ciphertexts: `e(P, W_1) * e(U_1, H1) * e(P, W_2) * e(U_2, H2) * ...`
    // We use an optimisation based on the billinearity property that implies: `\prod{e(P, W_i)} = e(P, \sum{W_i})`
    let g_inv = -G1::<P>::prime_subgroup_generator();
    let mut pairing_product: Vec<(
        <P::E as PairingEngine>::G1Prepared,
        <P::E as PairingEngine>::G2Prepared,
    )> = vec![];
    let mut auth_tag_sum: <P::E as PairingEngine>::G2Affine =
        <P::E as PairingEngine>::G2Affine::zero();
    for (c, ad) in ciphertexts.iter().zip(additional_data.iter()) {
        let tag_hash = construct_tag_hash::<P>(c.nonce, &c.ciphertext[..], ad);
        pairing_product.push((c.nonce.into(), tag_hash.into()));
        auth_tag_sum = auth_tag_sum + c.auth_tag;
    }
    pairing_product.push((g_inv.into(), auth_tag_sum.into()));

    let pairing_prod_result = P::E::product_of_pairings(&pairing_product[..]);
    if pairing_prod_result != <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::one()
    {
        return Err(ThresholdEncryptionError::CiphertextVerificationFailed);
    }

    // Decrypting each ciphertext
    let mut plaintexts: Vec<Vec<u8>> = Vec::with_capacity(ciphertexts.len());
    for (c, sh) in ciphertexts.iter().zip(shares.iter()) {
        plaintexts.push(share_combine_no_check(c, sh).unwrap().to_vec());
    }
    Ok(plaintexts)
}

pub fn batch_check_ciphertext_validity(additional_data: &[u8]) -> bool {
    // TODO
    false
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

        let plaintext = share_combine(ciphertext, ad, dec_shares).unwrap();
        assert!(plaintext == msg)
    }

    #[test]
    fn serialization_tests() {
        let mut rng = test_rng();
        let threshold = 3;
        let num_keys = 5;
        let (epk, svp, privkeys) = generate_keys::<TestingParameters, ark_std::rand::rngs::StdRng>(
            threshold, num_keys, &mut rng,
        );

        let epk_ser = bincode::serialize(&epk).unwrap();
        let epk_new: EncryptionPubkey<TestingParameters> = bincode::deserialize(&epk_ser).unwrap();
        assert!(epk_new.key == epk.key);

        let svp_ser = bincode::serialize(&svp).unwrap();
        let svp_new: ShareVerificationPubkey<TestingParameters> =
            bincode::deserialize(&svp_ser).unwrap();
        assert!(svp_new.decryptor_pubkeys == svp.decryptor_pubkeys);

        let privkeys_ser = bincode::serialize(&privkeys).unwrap();
        let privkeys_new: Vec<PrivkeyShare<TestingParameters>> =
            bincode::deserialize(&privkeys_ser).unwrap();
        for p in privkeys.iter().zip(privkeys_new.iter()) {
            let (p1, p2) = p;
            assert!(p1.index == p2.index);
            assert!(p1.privkey == p2.privkey);
            assert!(p1.pubkey == p2.pubkey);
        }

        let msg: &[u8] = "abc".as_bytes();
        let ad: &[u8] = "".as_bytes();
        let ciphertext = epk.encrypt_msg(msg, ad, &mut rng);
        let ciphertext_ser = bincode::serialize(&ciphertext).unwrap();
        let ciphertext_new: Ciphertext<TestingParameters> =
            bincode::deserialize(&ciphertext_ser).unwrap();
        assert!(ciphertext_new.nonce == ciphertext.nonce);
        assert!(ciphertext_new.ciphertext == ciphertext.ciphertext);
        assert!(ciphertext_new.auth_tag == ciphertext.auth_tag);

        let mut dec_shares: Vec<DecryptionShare<TestingParameters>> = Vec::new();
        for i in 0..num_keys {
            dec_shares.push(privkeys[i].create_share(&ciphertext, ad).unwrap());
        }
        let dec_shares_ser = bincode::serialize(&dec_shares).unwrap();
        let dec_shares_new: Vec<DecryptionShare<TestingParameters>> =
            bincode::deserialize(&dec_shares_ser).unwrap();
        for sh in dec_shares.iter().zip(dec_shares_new.iter()) {
            let (sh1, sh2) = sh;
            assert!(sh1.decryptor_index == sh2.decryptor_index);
            assert!(sh1.decryption_share == sh2.decryption_share);
        }
    }

    #[test]
    fn batch_share_combine_test() {
        let mut rng = test_rng();
        let threshold = 3;
        let num_keys = 5;
        let num_of_msgs = 4;

        let (epk, svp, privkeys) = generate_keys::<TestingParameters, ark_std::rand::rngs::StdRng>(
            threshold, num_keys, &mut rng,
        );

        let mut messages: Vec<[u8; 8]> = vec![];
        let mut ad: Vec<&[u8]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            ad.push("".as_bytes());
            let mut msg: [u8; 8] = [0u8; 8];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(epk.encrypt_msg(&messages[j], ad[j], &mut rng));

            dec_shares.push(Vec::with_capacity(num_keys));
            for i in 0..num_keys {
                dec_shares[j].push(privkeys[i].create_share(&ciphertexts[j], ad[j]).unwrap());
                assert!(dec_shares[j][i].verify_share(&ciphertexts[j], ad[j], &svp));
            }
        }

        let plaintexts = batch_share_combine(ciphertexts, ad, dec_shares).unwrap();
        assert!(plaintexts.len() != 0);
        for (p, m) in plaintexts.into_iter().zip(messages) {
            assert!(*p == m)
        }
    }
}
