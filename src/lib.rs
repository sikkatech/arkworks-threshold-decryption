use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand, Zero};

pub mod key_generation;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
