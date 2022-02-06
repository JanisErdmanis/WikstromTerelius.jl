module WikstromTerelius

using Infiltrator

using Mods: modulus, Mod

struct PrimeGenerator
    x::Mod
end

"""
We assume a prime order. That means (p - 1)/2 is a prime.
"""
PrimeGenerator(x::Integer, p::Integer) = PrimeGenerator(Mod{p}(x))


import Base.*
*(x::PrimeGenerator, y::PrimeGenerator) = PrimeGenerator(x.x*y.x)

import Base./
/(x::PrimeGenerator, y::PrimeGenerator) = PrimeGenerator(x.x / y.x)

import Base.==
==(x::PrimeGenerator, y::PrimeGenerator) = x.x == y.x

import Base.inv
inv(x::PrimeGenerator) = PrimeGenerator(inv(x.x))


import Mods.modulus
modulus(g::PrimeGenerator) = modulus(g.x)

import Mods.value
value(g::PrimeGenerator) = value(g.x)


order(g::PrimeGenerator) = (modulus(g) - 1) ÷ 2
validate(g::PrimeGenerator) = g.x != 1 && g.x^order(g) == 1


#Base.broadcast(::typeof(^), g::PrimeGenerator, v::Vector) = [g^i for i in v]


import Base.^
"""
Beacuse a prime order group is cyclic, in order to put it in power larger than that of it's order we can take it's mod.
"""
function ^(g::PrimeGenerator, n::Integer)
    n_mod = mod(n, order(g))
    #@assert n_mod != 0 "Power matches prime group order pointing to element {1}."
    n_mod==0 && (@warn "Power matches prime group order pointing to element {1}.")
    PrimeGenerator(g.x^n_mod)
end

style(x, n) = "\33[1;$(n)m$x\33[0m"

import Base.show
Base.show(io::IO, g::PrimeGenerator) = print(io, "$(value(g.x))" * style(" mod $(modulus(g.x)) (q = $(order(g)))", 90))

"""
A group is cyclic only if it's order is a prime. This function evaluates a prime modulo for a given prime order.
"""
safeprime(q::Integer) = 2*q + 1



### Now I need ElGammal encryption


struct Enc
    pk::PrimeGenerator
    g::PrimeGenerator
end

(enc::Enc)(m::PrimeGenerator, r::Integer) = (m*enc.pk^r, enc.g^r)
(enc::Enc)(r::Integer) = (enc.pk^r, enc.g^r)


const ElGamal = Tuple{PrimeGenerator, PrimeGenerator}

*(x::ElGamal, y::ElGamal) = (x[1]*y[1], x[2]*y[2])

(enc::Enc)(e::ElGamal, r) = e * enc(r)

# (enc::Enc)(e_vec::Vector{ElGamal}, r_vec::Vector{T}) where T <: Integer = [enc(e, r) for (e, r) in zip(e_vec, r_vec)]


struct Dec
    sk::Integer
end


(dec::Dec)(e::ElGamal) = e[1] * e[2]^(-dec.sk)


### So what about commitments

Base.isless(x::PrimeGenerator, y::PrimeGenerator) = value(x) < value(y)

Base.isless(x::ElGamal, y::ElGamal) = x[1] == y[1] ? x[2] < y[2] : x[1] < y[1]






function gen_shuffle(enc::Enc, e::Vector{ElGamal}, r::Vector{T}) where T <: Integer

    e_enc = enc.(e, r)
    ψ = sortperm(e_enc)
    sort!(e_enc)

    return e_enc, ψ
end




struct CRS
    g::PrimeGenerator
    𝐡::Vector{PrimeGenerator}
end

order(crs::CRS) = order(crs.g)


function trapdoor_crs(g::PrimeGenerator, N::Integer; trapdoors=rand(2:order(g), N) )
    
    h = [g^t for t in trapdoors]
    crs = CRS(g, h)

    return crs
end


function gen_commitment(crs::CRS, b::Vector, r::Integer)

    (; g, h) = crs
    com = g^r * prod(h .^ b)

    return com
end



function gen_perm_commitment(crs::CRS, 𝛙::Vector, 𝐫::Vector)

    (; g, 𝐡) = crs

    commitments = [g^𝐫[j] * 𝐡[i] for (i, j) in enumerate(𝛙)]
    sorted_commitments = commitments[𝛙]

    return sorted_commitments
end

function gen_commitment_chain(g::PrimeGenerator, c0::T, 𝐮::Vector, 𝐫::Vector) where T
    
    N = length(𝐮)

    𝐜 = Vector{T}(undef, N)

    𝐜[1] = g^𝐫[1] * c0^𝐮[1]

    for i in 2:N
        𝐜[i] = g^𝐫[i] * 𝐜[i-1]^𝐮[i]
    end
    
    return 𝐜
end


#hashx(x, q) = 2 + mod(hash("$x"), q - 2)
hashx(x, q) = 2 + mod(hash("$x"), q - 2)


∑(𝐱, q) = mod(sum(𝐱), q) ### Need to improve
∏(𝐱) = prod(𝐱)
∏(f, 𝐱) = prod(f, 𝐱)
# 𝓐𝓱 this is so beatifull \bscr<Letter>

using Random: default_rng, rand

function gen_proof(crs::CRS, 𝐞, 𝐞′, 𝐫′, 𝛙, pk; 
                   h = crs.𝐡[1],
                   rng = default_rng(),
                   𝐫 = rand(rng, 2:order(crs)-1, length(𝐞)), 
                   𝐫̂ = rand(rng, 2:order(crs)-1, length(𝐞)),
                   𝛚 = rand(rng, 2:order(crs)-1, 4),
                   𝛚̂ = rand(rng, 2:order(crs)-1, length(𝐞)),
                   𝛚̂′ = rand(rng, 2:order(crs)-1, length(𝐞)),
                   hash = (x...) -> hashx(x, order(crs)) # May also add modular collapse
                   )

    #@infiltrate

    @assert length(𝐞) == length(𝐞′) == length(𝐫′) == length(𝛙)
    N = length(𝐞)

    𝐚′ = (a′ for (a′, b′) in 𝐞′)
    𝐛′ = (b′ for (a′, b′) in 𝐞′)

    (; g, 𝐡) = crs
    q = order(g)

    𝐜 = gen_perm_commitment(crs, 𝛙, 𝐫)

    # I could use infiltrator here
    
    𝐮 = [hash((𝐞, 𝐞′, 𝐜), i) for i in 1:N] # The hash points to 0!
    𝐮′ = 𝐮[𝛙]

    #@infiltrate

    𝐜̂ = gen_commitment_chain(g, h, 𝐮′, 𝐫̂)
    
    𝐯 = Vector(undef, N)
    𝐯[N] = 1
    for i in N-1:-1:1
        𝐯[i] = 𝐮′[i+1] * 𝐯[i+1] 
    end

    r̄ = ∑(𝐫, q) 
    r̂ = ∑(𝐫̂ .* 𝐯, q)
    r̃ = ∑(𝐫 .* 𝐮, q)
    r′ = ∑(𝐫′ .* 𝐮, q)

    t₁ = g^𝛚[1] 
    t₂ = g^𝛚[2]

    t₃ = g^𝛚[3] * ∏(𝐡 .^ 𝛚̂′)

    t₄₁ = pk^(-𝛚[4]) * ∏(𝐚′ .^ 𝛚̂′)
    t₄₂ = g^(-𝛚[4]) * ∏(𝐛′ .^ 𝛚̂′)

    𝐭̂ = Vector(undef, N)
    𝐭̂[1] = g^𝛚̂[1] * h^𝛚̂′[1]
    for i in 2:N
        𝐭̂[i] = g^𝛚̂[i] * 𝐜̂[i-1]^𝛚̂′[i]
    end

    y = (𝐞, 𝐞′, 𝐜, 𝐜̂, pk)
    t = (t₁, t₂, t₃, (t₄₁, t₄₂), 𝐭̂) 
    c = hash(y, t)

    s₁ = mod(𝛚[1] + c * r̄, q)
    s₂ = mod(𝛚[2] + c * r̂, q)
    s₃ = mod(𝛚[3] + c * r̃, q)
    s₄ = mod(𝛚[4] + c * r′, q)
    
    𝐬̂ = mod.(𝛚̂ .+ c .* 𝐫̂, q) ### What can I do if I have a 0 as one of the elements?
    𝐬′ = mod.(𝛚̂′ .+ c .* 𝐮′, q)
    
    s = (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) # Do I need to ensure that `s` are without 0 elements

    π = (t, s, 𝐜, 𝐜̂)

    return π
end


function check_proof(crs::CRS, π, 𝐞, 𝐞′, pk; 
                     hash = hash = (x...) -> hashx(x, order(crs)),
                     h = crs.𝐡[1]
                     )

    (t, s, 𝐜, 𝐜̂) = π
    (s₁, s₂, s₃, s₄, 𝐬̂, 𝐬′) = s
    (t₁, t₂, t₃, (t₄₁, t₄₂), 𝐭̂) = t
    𝐚 = (a for (a, b) in 𝐞)
    𝐛 = (b for (a, b) in 𝐞)
    𝐚′ = (a′ for (a′, b′) in 𝐞′)
    𝐛′ = (b′ for (a′, b′) in 𝐞′)
    

    N = length(𝐞)

    (; g, 𝐡) = crs 
    q = order(g)
    
    𝐮 = [hash((𝐞, 𝐞′, 𝐜), i) for i in 1:N]    

    c̄ = ∏(𝐜) / ∏(𝐡)
    u = mod(∏(𝐮), q)
    
    ĉ = 𝐜̂[N] / h^u
    c̃ = ∏(𝐜 .^ 𝐮)

    a′ = ∏(𝐚 .^ 𝐮)
    b′ = ∏(𝐛 .^ 𝐮)

    y = (𝐞, 𝐞′, 𝐜, 𝐜̂, pk)

    c = hash(y, t)

    
    t₁′ = c̄^(-c) * g^s₁
    t₂′ = ĉ^(-c) * g^s₂
    t₃′ = c̃^(-c) * g^s₃ * ∏(𝐡 .^ 𝐬′)

    t₄₁′ = a′^(-c) * pk^(-s₄) * ∏(𝐚′ .^ 𝐬′)
    t₄₂′ = b′^(-c) * g^(-s₄) * ∏(𝐛′ .^ 𝐬′)

    𝐭̂′ = Vector(undef, N)

    #@infiltrate

    𝐭̂′[1] = 𝐜̂[1]^(-c) * g^𝐬̂[1] * h^𝐬′[1]    #ĉ0 = h

    for i in 2:N
        𝐭̂′[i] = 𝐜̂[i]^(-c) * g^𝐬̂[i] * 𝐜̂[i-1]^𝐬′[i]
    end

    @show t₁ == t₁′
    @show t₂ == t₂′ # this matches t₁
    @show t₃ == t₃′
    @show t₄₁ == t₄₁′
    @show t₄₂ == t₄₂′ 

    for i in 1:N
        @show 𝐭̂[i] == 𝐭̂′[i]
    end

    return true # About to change when I come so far. 
end



end # module

