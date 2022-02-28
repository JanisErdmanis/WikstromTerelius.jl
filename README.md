# # WikstromTerelius.jl
NIZK Proof of shuffle for reencryption mixnets

The non-interactive zero-knowledge proof of shuffle for reencryption mixnets is one of the most outstanding achievements of modern cryptography. I have implemented one of the simplest, most beautiful pseudocodes I have seen[^1], whose notation I follow with great care. 

## TODO:

  *  [x] Implement a prover and verifier
  *  [ ] Tidy things up. Perhaps if verification fails, introduce granularity on what part of the proof is invalid.
  *  [ ] Implement independent generator generation algorithm (Partially done in Verificatum.jl)
  *  [ ] Bridge the verifier with Verificatum, assuring implementation integrity.
     *  [x] Use the crypto primitives as in `Verificatum.jl`
     *  [x] Refactor verifier as a finite state machine
     *  [ ] Wrap `WikstromTerelius.jl` verifier for `Verificatum.jl` by mapping coresponding symbols. 
  *  [ ] Upstream relevant parts to `CryptoGroups.jl`

[^1]: Haenni et al., “Pseudocode Algorithms for Verifiable Re-Encryption Mix-Nets.”
