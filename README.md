# WikstromTerelius.jl
NIZK Proof of shuffle for reencryption mixnets

The noninteractive zero knowledge proof of shuffle for reencryption mixnets is one of the greatest achievements of modern cryptography. I have implemented the one of the simplest one of the most beatiful pseudocodes I have seen[^1] whoose notation I follow with great care. 

## TODO:

  *  [x] Implement a prover and verifier
  *  [ ] Tidy things up. Perhaps if verification fails intorduce granularity on what part of the proof is invalid.
  *  [ ] Implement independent generator generation algorithm (Parially done in Verificatum.jl)
  *  [ ] Bridge the verifier with Verificatum assuring integirity of implementation.
  *  [ ] Upstream relevant parts to `CryptoGroups.jl`

[^1]: Haenni et al., “Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets.”
