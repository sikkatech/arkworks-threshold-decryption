# arkworks-threshold-decryption
Pairing-based threshold decryption library

DO NOT USE IN PRODUCTION, VERY MUCH IN PROGRESS

This repository implements the threshold decryption scheme of [BZ03](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf). We implement two further optimizations to this scheme:
* One allows for 'additional data' to be augmented to the ciphertext, essentially achieving a threshold-decryptable AEAD scheme.
* The second allows for batching the decryption shares together, and to have the end-verifier only need to verify the combined decryption share.

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.