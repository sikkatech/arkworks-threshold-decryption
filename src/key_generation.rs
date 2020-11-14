use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, Polynomial, UVPolynomial,
};
use crate::{EncryptionPubkey, ShareVerificationPubkey, PrivkeyShare, Fr};

use rand_core::RngCore;

pub fn generate_keys<E: PairingEngine, R: RngCore> (threshold: usize, num_keys: usize, rng: &mut R) -> 
    (EncryptionPubkey<E>, ShareVerificationPubkey<E>, Vec<PrivkeyShare<E>>)
{
    assert!(num_keys >= threshold);
    let generator = E::G1Affine::prime_subgroup_generator();

    // Generate random degree t polynomial
    let threshold_poly = DensePolynomial::<Fr<E>>::rand(threshold - 1, rng);
    // threshold_poly(0) ... threshold_poly(num_keys)

    // Create "encryption pubkey"
    let zero_pt = <Fr::<E> as From<u64>>::from(0u64);
    let master_privkey : Fr::<E> = threshold_poly.evaluate(&zero_pt);
    let encryption_pubkey = EncryptionPubkey::<E>{ key: generator.mul(master_privkey).into() };

    // Create per-validator pubkey shares, and their privkey shares
    let mut pubkey_shares : Vec<E::G1Affine> = vec![];
    let mut privkeys = vec![];
    for i in 1..=num_keys 
    {
        let pt = <Fr::<E> as From<u64>>::from(i as u64);
        let privkey_coeff = threshold_poly.evaluate(&pt);
        pubkey_shares.push(generator.mul(privkey_coeff).into());

        let privkey = PrivkeyShare::<E>{
            index: i,
            privkey: privkey_coeff,
            pubkey: pubkey_shares[i - 1],
        };
        privkeys.push(privkey);
    }
    let verification_pubkey = ShareVerificationPubkey::<E>{ decryptor_pubkeys: pubkey_shares };
    
    (encryption_pubkey, verification_pubkey, privkeys)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
