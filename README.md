# arkworks-threshold-decryption
Pairing based threshold decryption library

This repository implements the threshold decryption scheme of [BZ03](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf). We implement a further optimization to this scheme to allow for 'additional data' to be augmented to the ciphertext, essentially achieving a threshold-decryptable AEAD scheme.

TODO:
- [ ] Have Sage Prototypes
- [ ] Figure out how to nicely template curve+AEAD choice.
- [ ] Implement 'Dummy Key Generation'
- [ ] Implement 'Threshold encrypt'
- [ ] Implement Check-ciphertext
- [ ] Implement Check-decryption share
- [ ] Implement creating a decryption share
- [ ] Implement combining decryption shares
- [ ] Implement a method to guarantee that a plaintext is truly the decryption of the ciphertext
- [ ] Write proofs of missing components from the original paper
- [ ] Learn how to zeroize secrets in Rust
- [ ] Talk to Tony for bug things

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.