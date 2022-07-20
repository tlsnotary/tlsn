## Background

The User wants to encrypt a TLS request with some server, but she doesn't have the encryption key. Rather she has just one share of the key. The Notary has the other share. The Notary needs to know that the only ciphertext sent to the TLS server is the ciphertext he has seen (it would be bad, e.g., if the User had the full key because she lie to the Notary about the request she sent). We want a 2PC scheme that will allow the User and Notary to collaboratively compute the ciphertext such that: the User does not reveal her plaintext or key share, and the Notary does not reveal his key share.

## Idea

We make two observations. Firstly, a small amount of keyshare leakage is tolerable. E.g., if the Notary leaks 3 bits of their keyshare, it gives the User no meaningful advantage in any attack, as she could have simply guessed the bits correctly with 12% probability and mounted the same attack.

Secondly, we observe that the Notary's keyshare is an _ephemeral secret_: it is only private for the duration of the User's TLS session. This implies two things:

1. The User is free to learn the encryption key after she has received and committed to the TLS response. Thus, if the parties wait until the end of the TLS session to do maliciousness checks, then they can reap the benefits of the Notary having no private inputs.
2. Since the encryption key is not a long-term secret, okay if a malicious User prematurely learns the entire thing, _so long as it is detected_. Thus, the parties are free to engage in potentially leaky MPC early on, so long as checks are performed at some point.

## Prelims

* `p` is the User's plaintext request
* `k` is the AES key
* `[k]₁` and `[k]₂` are the User's and Notary's AES keyshares, respectively
* `Enc` denotes the encryption algorithm used by the TLS session
* `Com(x; r)` denotes a commitment to `x` with randomness `r`

## Ideal functionality

We define the ideal functionality we wish to instantiate. In words, the functionality uses the parties' keyshares to encrypt the User's TLS request, and send the ciphertext to both parties. The functionality then waits for the user to get and commit to the TLS response, and then releases the encryption key to the User.
```
Ideal functionality for ONESHOTENC:
    User → ℱ: p, [k]₁
    Notary → ℱ: [k]₂
    ℱ → User: Enc_k(p)
    ℱ → Notary: Enc_k(p)
    User → ℱ: com_resp := Com(resp; r) for random r
    ℱ → User: k
    ℱ → Notary: com_resp
```

## Open questions

* Does the user have to commit to the server response? It's a ciphertext, so why not just send the unblinded hash?
* Is the encryption here an AEAD or just the CTR part of AES-GCM? If the Notary only learns the ciphertext without the auth tag, can the user open it to garbage later on?

## Protocol

We now describe the protocol at a high level.

### Part 1

The first step is for the User to get the ciphertext. The User does not trust the Notary, and the User's data is far more sensitive to leakage than the Notary's. So the parties do an ordinary MPC (with malicious OT):

1. The User sends the garbled encryption circuit and garbled wires for `[k]₁` and `p`.
2. The Notary evaluates on `[k]₂`, derives the ciphertext `c`, and sends `c` to the User

At this point, the Notary (even if malicious) has learned nothing about the key or plaintext. They have learned the ciphertext though, which they will use later to ensure the User was honest in their garbling. 

Also at this point, the User has learned the ciphertext, and, if malicious, has potentially learned the entire key `k`. As mentioned in the second observation above, it is okay if the User was malicious and learned `k`, but the Notary has to detect it and then abort the rest of the TLSNotary protocol. Before this step, the Notary waits for the User to complete their TLS session:

### Part 2

3. The User completes her TLS session and sends `com_resp = Com(resp; r)`

### Part 3

Now that the session is over and `k` is no longer secret, the Notary begins the maliciousness check. Taking a page out of the Dual-Execution method, the Notary will check that the User can derive the same ciphertext, given the full key. If she can, then the MPC done in Part 1 was performed honestly, and nothing prematurely leaked to the User.

To do this check, the Notary will do a privacy-free garbling to compute `Enc_k(p)` where `k` and `p` are known only to the User:

4. The Notary sends `[k]₂` and a garbled encryption circuit to the User. He does _not_ send the decoding information to the User
5. The User derives `k` and evaluates the circuit on `k` and `p`, getting as a result the encoded ciphertext `C'`. She commits `com_C' := Com(C'; r')` for some randomness `r'` and sends `com_C'` to the Notary.
6. The Notary opens the garbled circuit to the User, revealing all the wire labels (this can be done e.g., by sending a PRG seed ρ that was used to generate the wire labels).
7. The User checks that the opening is well-formed and consistent with the wire labels and gates she received earlier. On success, she opens her commitment, sending `C'` and `r'` to the notary.
8. The notary checks the commitment opening and decodes `C'` to ciphertext `c'`. Finally the Notary verifies that `c == c'`. On success, the Notary outputs success.

To recap, the Notary forced the User to produce the ciphertext `c'` herself, and then checked that it was equal to the ciphertext he saw earlier. If this is the case, then nothing prematurely leaked to the User.

------------------------------

**Dan's text:**

## Idea

It is possible to fix the GCDE leak by synthesizing multiple ideas: avoiding GCDE equality check, having the User (U) regenerate Notary's (N) circuits and building the decoding table from the hashes of labels.

Note that this protocol only fixes the leak by a malicious N. If the U is malicious, she may still guess N's AES keys' bits as per GCDE's 1-bit leakage. (but we already concluded that leaking bits of the AES key is not a threat).


## Prelim

Each party already has the to-be-evaluated GC sent by the other party and all the necessary input labels.

## Steps

1. The GC (for the Request) which each party evaluates has the following input/output:

- N's inputs: TLS key share,
- U's inputs: TLS key share, plaintext
- Output: `Request's ciphertext`

2. U sends `HashedLabels`: hashes of all output label pairs. See Step 12 on why this is necessary.

3. N evaluates the GC, obtains `N's active output labels`, sends them to U.

4. U decodes `N's active output labels` into `Request's ciphertext` and trusts that the `Request's ciphertext` is legitimate.

5. User sends the `Request's ciphertext` (with a MAC) to the Server.

6. Parties finish the Phase 1 of the TLSNotary protocol.

The purpose of all the steps below is for U to convince the N that the U's GC (which N evaluated) did not leak the N's secret via the circuit's output. While doing the convincing, U must avoid the GCDE equality check which would leak U's plaintext bits to N.

7. U evaluates the GC and sends `ComU`: a commitment to `U's active output labels`. 

8. N reveals the randomness `seed` of his GC.

9. U re-generates N's GC from the `seed` and aborts if the generated GC doesn't match the GC which she evaluated in Step 7.

Because the GC was generated correctly, U knows that the decoding of (her) `U's active output labels` (from Step 7) matches `Request's ciphertext` (from Step 4), so it is safe to proceed with the next step.

10. U opens `ComU` (from Step 7) and reveals `U's active output labels`.

11. N decodes `U's active output labels` into `ciphertext1` and trusts that `ciphertext1` is legitimate.

12. N hashes his `N's active output labels` (from Step 3) and decodes them into `ciphertext2` using `HashedLabels` from Step 2.

Note that if instead of revealing the hashes of the labels, U revealed the labels themselves, that would reveal GC's delta to N and break GC security.

13. N checks that `ciphertext1` == `ciphertext2`.


The same protocol works also for multi-round TLS session when the Server Response has to be decrypted in the online phase.
The GC which the parties would use is:

- N's inputs: TLS key share
- U's inputs: TLS key share, ciphertext mask
- Output: (plaintext XOR mask)

The reason why the mask is needed is to hide the plaintext from the Notary.
