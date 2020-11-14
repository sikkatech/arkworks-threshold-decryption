use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand, Zero};

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


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
