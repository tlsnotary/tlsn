Prevent plaintext leak of the Request (for the Response see * at the bottom) by a malicious Notary.

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
