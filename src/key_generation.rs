use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations as EvaluationsOnDomain,
    GeneralEvaluationDomain, Polynomial, UVPolynomial,
};

use rand_core::RngCore;


type Fr<E: PairingEngine> = <E::G1Affine as AffineCurve>::ScalarField;

pub struct Pubkey<E: PairingEngine, n: usize> {
    pub masterkey : E::G1Affine,
    pub per_node_pubkey : [E::G1Affine; n],
}

pub struct PrivkeyShare<E: PairingEngine> {
    pub index : usize,
    pub privkey : Fr<E>,
    pub pubkey : E::G1Affine,
}


pub fn generate_keys<E: PairingEngine, R: RngCore> (threshold: usize, num_keys: usize, rng: &mut R) 
{
    assert!(num_keys >= threshold);
    let generator = E::G1Affine::prime_subgroup_generator();

    // Generate random degree t polynomial
    let threshold_poly = DensePolynomial::<Fr<E>>::rand(threshold - 1, rng);
    // threshold_poly(0) ... threshold_poly(num_keys)

    // Create "master pubkey"
    let zero_pt = <Fr::<E> as From<u64>>::from(0u64);
    let master_privkey : Fr::<E> = threshold_poly.evaluate(&zero_pt);
    let master_pubkey = generator.mul(master_privkey).into();

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

}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
