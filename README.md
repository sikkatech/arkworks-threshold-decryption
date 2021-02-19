# arkworks-threshold-decryption
Pairing based threshold decryption library

DO NOT USE IN PRODUCTION, VERY MUCH IN PROGRESS

This repository implements the threshold decryption scheme of [BZ03](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf). We implement two further optimizations to this scheme. 
One allows for 'additional data' to be augmented to the ciphertext, essentially achieving a threshold-decryptable AEAD scheme.
The second allows for batching the decryption shares together, and to have the end-verifier only need to verify the combined decryption share.

TODO:

- [ ] Figure out how to nicely template curve+AEAD choice.
- [ ] Finish arkworks Hash To Curve PR, and switch API to that
- [x] Implement 'Dummy Key Generation'
- [X] Implement 'Threshold encrypt'
- [X] Implement Check-ciphertext
- [ ] Implement Check-decryption share
- [X] Implement creating a decryption share
- [ ] Implement Lagrange coefficient generation
- [ ] Upstream Lagrange coefficient generation
- [ ] Implement combining decryption shares
- [ ] Implement a method to guarantee that a plaintext is truly the decryption of the ciphertext
- [ ] Implement serialization methods for structs
- [ ] Write proofs of missing components from the original paper
- [ ] Prove our custom decryption share verification system
- [ ] Zeroize secrets
- [ ] Talk to Tony for how to do bug reporting

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.