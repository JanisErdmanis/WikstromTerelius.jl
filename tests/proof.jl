using Test
using WikstromTerelius: ElGamal, PrimeGenerator, prove, verify, Simulator, Enc, Dec, gen_shuffle, Verifier, PoSChallenge, Shuffle

import WikstromTerelius: step, challenge, PoSChallenge


@enum VState Config Init PermCommit PoSCommit

### 
struct HonestVerifier{T} <: Verifier
    challenge::PoSChallenge
end

HonestVerifier(challenge::PoSChallenge) = HonestVerifier{Config}(challenge)
HonestVerifier{T}(verifier::HonestVerifier) where T = HonestVerifier{T}(verifier.challenge)

PoSChallenge(verifier::HonestVerifier{PoSCommit}) = verifier.challenge

step(verifier::HonestVerifier{Config}, proposition::Shuffle) = HonestVerifier{Init}(verifier)
step(verifier::HonestVerifier{Init}, 𝐜) = HonestVerifier{PermCommit}(verifier)
step(verifier::HonestVerifier{PermCommit}, 𝐜̂, t) = HonestVerifier{PoSCommit}(verifier)
#step(verifier::HonestVerifier{PoSCommit}, s) = HonestVerifier{End}(verifier)


challenge(verifier::HonestVerifier{Init}) = (verifier.challenge.𝐡, verifier.challenge.𝐡[1])
challenge(verifier::HonestVerifier{PermCommit}) = verifier.challenge.𝐮
challenge(verifier::HonestVerifier{PoSCommit}) = verifier.challenge.c


p = 23
g = PrimeGenerator(3, p) 

sk = 5
pk = g^sk

enc = Enc(pk, g)
dec = Dec(sk)


𝐦 = [g, g^2, g^3]
𝐞 = enc(𝐦, [2, 3, 4])

N = length(𝐞)

𝐡 = [g^i for i in 2:N+1]


𝐫′ = [4, 2, 3] 
proposition, secret = gen_shuffle(enc, 𝐞, 𝐫′) # In practice total of random factors can't match as it reveals 


(; 𝛙) = secret
(; 𝐞, 𝐞′) = proposition
@test dec(𝐞)[𝛙] == dec(𝐞′)


𝐡 = [g^i for i in 2:N+1]
𝐮 = [3, 4, 5]
c = 9

chg = PoSChallenge(𝐡, 𝐮, c)

verifier = HonestVerifier(chg)

simulator = prove(proposition, secret, verifier)

@test verify(simulator)
