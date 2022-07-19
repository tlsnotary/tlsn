# The AUTHDECODE Protocol

This document describes a protocol that runs after a garbled-circuit two-party computation, that allows the receiver to obtain a signed commitment to their output labels (with the sender being the signing party). This protocol is generic over choice of polynomial commitment scheme and garbled-circuit implementation.

## Background

Parties called the Notary (aka "Sender") and Requester (aka "Receiver") perform some 2-party garbled-circuit computation together. At the end, the Requester has "garbled bits" or "labels" `wᵢ ∈ 𝔽` (where 𝔽 is a finite field; see "Note on arithmetic delta" below for an explanation of why this isn't an unstructured 128-bit string). When decoded, each `wᵢ` will reveal the i-th bit of the output of the 2-party computation.

## Goal

The Requester needs the Notary to affirm that the resulting plaintext is the correct output of the 2PC protocol. Concretely, The Requester wants to decode `w` to plaintext `P`, and have the Notary sign a commitment to `P` _without_ the Notary learning `w` or `P`.

## First steps

We first describe our protocol at a high level.

Before anything happens, the Requester needs to commit to `w`. They then receive the full set of labels `W` and decode `w` to bits `p` (decoding is just testing whether wᵢ equals Wᵢ₀ or Wᵢ₁; if it equals the former, then we say `pᵢ = 0`; if it equals the latter, then we say `pᵢ = 1`; if neither is true then error). The requester also _packs_ the bitstring into a bytestring `P` for ease of use later. In order to convince the Notary that `com_P` is the correct value, the Requester first needs to prove that `W_p = w`, i.e., the decoding of `w` wrt `W` is `p`. They do this by exploiting an algebraic relation, and using homomorphic polynomial commitments. Note `W_p = w` is equivalently
```
∀i : wᵢ = W_{i,0} + pᵢ·(W_{i,1} - W_{i,0})
```
Stating that in vector form,
```
w = W₀ + pΔ
```
where `W₀ = (W₁₀, ..., Wₙ₀)` (the "zeros" vector) and `Δ` is the global "delta", equal to `Wᵢ₁ - Wᵢ₀` for all `i` (see "Note on arithmetic delta" below for more detail). The Requester uses a polynomial commitment scheme to prove this relation without revealing `w` or `p`. They then pack `p` into `P` (and prove the commitments are compatible) and finally have the Notary sign `com_P`.

## Open questions

* When precisely is `R_binary` ZK? Is two blinders sufficient? Is there an easier way to prove it ZK?
* `R_decode` should be a simple polyn equality check where everything important is public. Someone familiar with Mina's commitment scheme should figure out the best protocol for that.
* How efficient is our protocol below? How many polynomial evals and proofs are necessary (it looks like we have 3 eval proofs rn, plus a large sigma protocol proof)? Can we optimize further? What about batching to ease verification?
* What can you do with `com_P` once you have it? It's a Pedersen commitment to a bytestring, which is nice, but how fast would a substring proof concretely be? You'd presumably have to do an inclusion proof for every byte, and then batch them at the end.
* Relatedly, can we do "conversion proofs", i.e., proofs that let you convert `com_P` from one commitment scheme to another? Concretely, this is a proof that shows that there exists a `(σ, com_P)` that are consistent with a new `com_P'` which uses a different commitment scheme. You can imagine a proof π that proves `σ` is a valid signature of `com_P`, and that `com_P'` is the Poseidon hash of `P`. Then to prove a predicate `φ` over `P` to a third party, you construct a recursive ZKP that verifies π wrt `com_P'` (public) and `σ` (hidden) and `com_P` (hidden), and proves `φ(P) = 1`. Opening `P` inside π might be expensive, but one possible optimization is to pack 255 bits at a time rather than just 8.
* In reality, the Requester actually knows `p` in advance. Can we leverage that to give us any concrete speedups?
* What malicious- and cover-secure schemes are compatible with doing the arithmetic delta trick at the end? Cut and choose is an easy fit, for example.

## Prelims

Some terminology:

* Let `PolyCom, PolyWit, PolyVfyWit, PolyOpen, PolyVfyOpen` be a polynomial commitment scheme over a finite field 𝔽
* Let `ck` denote the polynomial "commitment key"
* Let `n` be the number of bits in the plaintext
* Let `ω` be a primitive N-th root of unity for N ≥ n
* Let `λᵢ(X)` be the i-th Lagrange basis polynomial over `{ωⁱ}_i=1^N`
* Let `W` be the set of all labels. Labels are 128-bit values.
* Let `W₀` denote the labels in `W` corresponding to the 0 bits, and `W₁` to the 1 bits.
* Let `Δ` be the global "delta" `Δ = Wᵢ₁-Wᵢ₀` for all `i`
* Let `ρ` be a PRG seed such that `PRG(ρ) = W`
* Let `w` be a vec of `n` labels, known only to Requester
* Let `interp(v)` map a vector `v = (v₁, ..., vₛ)` to its interpolated polynomial representation `Σ_{i=1}^s vᵢλᵢ(X)`

## The AUTHDECODE functionality

We formalize our goal as an ideal functionality. In words, the below functionality takes the Requester's output labels, and gives it back its decoding, plus a signed commitment of the (packed) decoding. Note the Notary doesn't actually send the labels, rather it sends the PRG seed used to generate those labels.
```
Ideal functionality for AUTHDECODE:
    Requester → ℱ: w
    Notary → ℱ: ρ, sk
    ℱ → Requester:
        Let W = PRG(ρ)
        Let p be the decoding of w wrt W
        If decoding fails: abort
        Else: return P, r, σ
          where,
            r is randomness
            P = pack(p)
            N = n/8
            com_P = Com(P; r)
            σ = Sign_sk(N || com_P),
```

## Protocol

To start, we write a full real world protocol that instantiates the AUTHDECODE functionality. This makes use of various subprotocols, which we define below.
```
Impl for AUTHDECODE
    Requester → Notary:
        // Requester must commit to w before it learns the decoding
            Send com_w = PolyCom(ck, w)
    Requester ← Notary:
        // ρ is sufficient to derive the full label set W
            Send ρ
    Requester → Notary:
        // Reconstruct W and decode w into plaintext bits p
            Let W = PRG(ρ)
            Let p = Decode(w, W) or abort
            Let P = pack(p)
        // Commit to everything
            Let com_p = PolyCom(ck, p)
            Let com_P = PolyCom(ck, P)
            Send (com_p, com_P)
    Requester ↔ Notary:
        // p is the decoding of w wrt W
            Prove R_decode over (W₀, Δ, com_w, com_p; p, w)
        // P is the packing of p
            Prove R_pack over (com_P, com_p, ck; P, p)
    Requester ← Notary:
        // Everything succeeded, sign the length and commitment
            Let N = n/8
            Send σ = Sign_sk(N || com_P)
```

## Subprotocols

Below we define the relations `R_decode`, `R_shiftcom`, and `R_pack`, and write ZK protocols for them.

`R_decode` states that `p` is the decoding of `w` with respect to `W = W₀ || W₀ + (Δ, ..., Δ)`.

**NOTE:** The protocol here seems suboptimal. In reality, we only need to prove the polynomial equality `W₀ = w - Δp`, where we have commitments to `w, p` and `W₀, Δ` are public. This should be very simple.
```
R_decode = {
    (W₀, Δ, com_w, com_p, n; p, w) :
      w = W₀ + pΔ
    ∧ PolyVfyOpen(ck, com_w, w)
    ∧ PolyVfyOpen(ck, com_p, p)
}
Protocol
    Prover ↔ Verifier:
        // Prove that p is binary
            Prove R_binary over (ck, com_p, n; p)
    Prover ← Verifier:
            Sample and send a challenge point c
    Prover → Verifier:
        // Evaluate the LHS of the equation W₀ = w - Δp at c
            Let com_W₀ = PolyCom(ck, W₀; 0)
            Let com_d = com_w - Δ·com_p
            Let π₁ = PolyWit(ck, W₀, com_d, (c, W₀c))
        // The prover evals W₀(c) even though the verifier
        // could do it. This is to save verif. cost.
            Let W₀(X) = interp(W₀)
            Let W₀c = W₀(c)
            Let π₂ = PolyWit(ck, W₀, com_W₀, (c, W₀c))
            Send (com_d, W₀c, π₁, π₂)
    Verifier:
        // Check the eval on W₀
            Let com_W₀ = PolyCom(ck, W₀; 0)
            Check PolyWitEval(ck, π₂, com_W₀, (c, W₀c))
        // Then verify the same eval wrt the RHS commitment
            Let com_d = com_w - Δ·com_p
            Check PolyWitEval(ck, π₁, com_d, (c, W₀c))
```

`R_binary` states that `com_p` is binary. This may only be ZK if `p` has two blinders in it. Say at positions `n+1` and `n+2`.
```
R_binary = {
    (ck, com_p, n; p):
    p(ωⁱ) ∈ {0,1} for all i = 1, ..., n
}
Protocol:
    Prover → Verifier
        // To prove binaryness it suffices to show p ⊙ (p-1ⁿ) = 0ⁿ
            Let p(X) = interp(p)
            Let 1ⁿ = (1, 1, ..., 1) // Note: This is the geometric series
            Let p¹(X) = p(X) - interp(1ⁿ)
            Let com_p¹ = com_p - PolyCom(ck, 1ⁿ; 0)
        // Let z = p · (p - 1ⁿ) = p ⊙ (p-1ⁿ) || garbage. We want to show that
        // the first n coeffs of z are 0. Equivly, z(ωⁱ) = 0 for all
        // i = 1, ..., n. Also equivly, Π₁ⁿ (X - ωⁱ) divides z(X).
            Let v(X) = Π (X - ωⁱ)  // the "vanishing set polyn"
            Let q(X) = z(X) / v(X) // the "quotient polyn"
            Let com_q = PolyCom(ck, q)
        // Send a commitment to q so the verifier can check
        // that v(X) · q(X) == z(X) == p(X) · p¹(X).
            Send com_q
    Prover ← Verifier:
        Sample and send a challenge point c
    Prover → Verifier:
        // Eval the polyns at the challenge point
            Let qc = q(c)
            Let pc = p(c)
        // Prove the evals for the quotient statement
            Let π₁ = PolyWit(ck, q, (c, qc))
            Let π₂ = PolyWit(ck, p, (c, pc))
            Send (qc, pc, π₁, π₂)
    Verifier:
        // Check the evals
            Check PolyVfyWit(ck, π₁, com_q, (c, qc))
            Check PolyVfyWit(ck, π₂, com_p, (c, pc))
        // Check q(c)·v(c) == z(c) == p(c) · p¹(c), i.e., that v | z
            Let vc = v(c)
            Let 1c = 1ⁿ(c)
            Check vc · qc == pc · (pc - 1c)
```

`R_pack` states that the bytestring `P` is the packing of the bitstring `p`, where just `com_P` and `com_p` are given. We follow the generic sigma-protocol framework described in Fig. 3 of "Unifying Zero-Knowledge Proofs of Knowledge" by Maurer. We make a homomorphism φ: 𝔽[X] → (𝔾, 𝔾) such that our plaintext `p` gets mapped to `(com_p, com_P)` where `P = pack(p)`. Thus, proving knowledge of a preimage of `(com_p, com_P)` proves that `P` is the packing of `p`. Note this protocol is very simple and likely very fast, but its overhead is nontrivial: a packing proof of a 4KB (= 32kb) plaintext is itself ~1MB.
```
R_pack = {
    (com_P, com_p, ck; p, P) :
      PolyVfyOpen(ck, p, com_p)
    ∧ PolyVfyOpen(P, com_P)
    ∧ P = pack(p)
}
Protocol: // This is almost identical to a Schnorr identity proof
    Define φ(r) = (
        rᵢG₁ + ... + r_{8i}·G_{8i}, // Commitment to r
        q₁G₁ + ... + qₙGₙ,          // Commitment to pack(r)
    ), where
         ck = (G₁, ..., G_{8i})
         qᵢ = r_{8i} + 2·r_{8i+1} + ... + 2⁷·r_{8i+7}

    Prover → Verifier:
        Sample polyn k uniformly, where deg k = deg p
        Let K = φ(k)
        Send K
    Prover ← Verifier:
        Sample and send a challenge scalar c
    Prover → Verifier:
        Send s = k + c·p
    Verifier:
        Check that φ(s) = K + c·(com_p, com_P)
```

## Authenticated OT

The above technique also works for getting a signature on committed _input_ to a garbled circuit. Suppose an Evaluator evaluates a garbled circuit on encoded input `w` (each `wᵢ` is derived via OT), and returns the encoded output `o` to the Garbler.

If the Evaluator wants to prove knowledge of the encoding of the plaintext `p` that produced `o`, it suffices to show that the encoding `w` is a subset of the full set of the Evaluator's input labels (this is guaranteed by authenticity). To do this, the evaluator commits to `w` at any point during the evaluation, and sends `com_w` to the Garbler. After evaluation, the Garbler reveals all of the input wires `W`. Then the AUTHDECODE protocol proceeds as normal, constructing a plaintext input commitment `com_p` and showing  that it is compatible with `com_w` and `W`.

More succinctly, AUTHDECODE on input labels is equivalent to authenticated OT: it proves that the committed values are a subset of all the Evaluator's input labels. By authenticity of MPC, authenticated OT immediately yields a method for constructing authenticated MPC inputs.

## Note on arithmetic delta

Ordinarily, the output labels of a 2PC garbled circuit computation are 128-bit strings `wᵢ ∈ {0,1}¹²⁸`. But for the protocol above to work, `wᵢ` need to have algebraic structure. Fortunately, we can assume without loss of generality that this is the case.

For suppose the output labels `Wᵢⱼ' ∈ {0,1}¹²⁸` of a 2PC garbled circuit do not have algebraic structure. Then the garbler can add an identity gate to each output, encoding the new algebraic labels `Wᵢⱼ ∈ 𝔽` such that `Wᵢ₁ = Wᵢ₀ + Δ` for all `i`, where `Δ ∈ 𝔽` is sampled uniformly. The `Wᵢⱼ` may be generated using whatever method the rest of the garbled circuit uses, e.g., from a PRG seed ρ or truly randomly. Similarly, the identity gate is encoded using whatever method the rest of the garbled circuit uses, e.g., point-and-permute or trial decryption.

Thus, we have constructed a garbled circuit whereby each output wire `wᵢ` is a random field element, and each column of `W ∈ 𝔽²ⁿ` is related by a global, uniform `Δ`.

**Security:** As with ordinary labels, malformed arithmetic labels can be abused to leak information to the garbler. This is addressed in the same way as in the underlying garbled circuit, e.g., doing cut-and-choose for malicious security or, in the privacy-free case, revealing all the labels after the output labels have been committed to.
