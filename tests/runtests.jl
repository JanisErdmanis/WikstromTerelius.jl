using WikstromTerelius: PrimeGenerator, safeprime, validate, order, Enc, Dec, modulus, value, gen_shuffle


q = 11
p = safeprime(q)

#g^(div(p - 1), 2)

# Checking prime order

@assert validate(PrimeGenerator(3, p)) == true
@assert validate(PrimeGenerator(11, p)) == false

n = let 
    n = 0
    for i in 1:p
        validate(PrimeGenerator(i, p)) && (n+=1)
    end
    n
end
@assert n == q - 1



g = PrimeGenerator(3, p)

#q = 17
#g = PrimeGenerator(3, q)

@assert g*g^2 == g^3
@assert (g^2)^2 == g^4
@assert g^(order(g) + 1) == g

h = g^7

@assert h*h^2 == h^3
@assert (h^2)^2 == h^4
@assert h^(order(h) + 1) == h


@assert inv(g)*g^2 == g
@assert (g^7)^6 == g^(7*6) # This is only true for a cyclic group
@assert g*g*g == g^3 # Checking multiplication
@assert g^2/g == g



### Let's test ElGammal encryption


sk = 5
pk = g^sk
r = 3
m = g^5
r2 = 4

enc = Enc(pk, g)
dec = Dec(sk)

@assert dec(enc(m, r)) == m
@assert enc(enc(m, r), r2) == enc(m, r + r2)

### Shuffle generation

sk = 5
pk = g^sk

enc = Enc(pk, g)


m_vec = [g, g^2, g^3]
e_vec = enc.(m_vec, 1) # It is not necessary to randomize encryption for user. It however does make sense to do so for intermidiatery who collects messages from users to not reveal internals. 

### The shuffling
r_vec = Int[1, 2, 3]

e_enc = enc.(e_vec, r_vec)
ψ = sortperm(e_enc)
sort!(e_enc)

@assert sort(dec.(e_enc)) == sort(m_vec)


m_vec = [g, g^2, g^3]
e_vec = enc.(m_vec, 1)

e_enc, ψ = gen_shuffle(enc, enc.(m_vec, 1), [1, 2, 3])

###

using WikstromTerelius: trapdoor_crs, gen_commitment, gen_perm_commitment, gen_commitment_chain, gen_proof, check_proof

g = PrimeGenerator(3, p)

crs = trapdoor_crs(g, 3; trapdoors=[6, 7, 5])


### So this indeed works as an inverse!
sinv(s, q) = gcdx(s, q)[2]

# The hash function I will provide as an argument


𝐦 = [g, g^2, g^3]
𝐞 = enc.(𝐦, 1)

𝐫′ = [1, 2, 3]
𝐞′, 𝛙 = gen_shuffle(enc, 𝐞, 𝐫′) # In practice total of random factors can't match as it reveals 

𝐫 = [2, 3, 4]
c = gen_perm_commitment(crs, 𝛙, 𝐫)

𝐮 = [3, 4, 5]
c_chain = gen_commitment_chain(crs.g, crs.𝐡[1], 𝐮, 𝐫)


π = gen_proof(crs, 𝐞, 𝐞′, 𝐫′, 𝛙, pk)

check_proof(crs, π, 𝐞, 𝐞′, pk)


