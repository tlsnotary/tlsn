## Background

The User wants to encrypt a TLS request with some server, but she doesn't have the encryption key. Rather she has just one share of the key. The Notary has the other share. The Notary needs to know that the only ciphertext sent to the TLS server is the ciphertext he has seen (it would be bad, e.g., if the User had the full key because she'd lie to the Notary about the request she sent). We want a 2PC scheme that will allow the User and Notary to collaboratively compute the ciphertext such that: the User does not reveal her plaintext or key share, and the Notary does not reveal his key share.

## Observations

We make two observations. Firstly, a small amount of keyshare leakage is tolerable. For example, if the Notary leaks 3 bits of their keyshare, it gives the User no meaningful advantage in any attack, as she could have simply guessed the bits correctly with $1/2^3 = 12.5$% probability and mounted the same attack.

Secondly, we observe that the Notary's keyshare is an _ephemeral secret_: it is only private for the duration of the User's TLS session. This implies two things:

1. The User is free to learn the encryption key after she has received and committed to the TLS response. Thus, if the parties wait until the end of the TLS session to do maliciousness checks, then they can reap the benefits of the Notary having no private inputs.
2. Since the encryption key is not a long-term secret, it is okay if a malicious User prematurely learns the entire key, _so long as it is detected_. Thus, the parties are free to engage in potentially leaky MPC early on, so long as checks are performed at some point.

## Prelims

* $p$ is the User's plaintext request
* $k$ is the AES key
* $[k]\_1$ and $[k]\_2$ are the User's and Notary's AES keyshares, respectively. That is, $k = [k]\_1 \oplus [k]\_2$.
* $\mathsf{Enc}$ denotes the encryption algorithm used by the TLS session
* $\mathsf{PRG}$ denotes a pseudorandom generator
* $\mathsf{com}_x$ denotes a binding commitment to the value $x$

## Ideal functionality

We define the ideal functionality we wish to instantiate. In words, the functionality uses the parties' keyshares to encrypt the User's TLS request, and send the ciphertext to both parties. The functionality then waits for the user to get and commit to the TLS response, and then releases the encryption key to the User.

Ideal functionality for ONESHOTENC:

1. User → ℱ: $p, [k]\_1$
2. Notary → ℱ: $[k]\_2$
3. ℱ → User: $\mathsf{Enc}\_k(p)$
4. ℱ → Notary: $\mathsf{Enc}\_k(p)$
5. User → ℱ: $\mathsf{com}\_\mathsf{resp}$
6. ℱ → User: $k$
7. ℱ → Notary: $\mathsf{com}\_\mathsf{resp}$

## Protocol

We now describe the protocol at a high level. It is based on Figure 1 of the [Dual-Execution (DualEx) technique](https://www.cs.virginia.edu/~evans/pubs/oakland2012/quidproquotocols.pdf) with a relaxation (see Step 3 below). We overcome DualEx's inherent 1-bit leakage by introducing a consistency check which the User performs on the Notary, thus removing the ability to leak the User's input. It is still possible for a malicious User to leak the Notary's input (i.e. the AES key share), but it gives her no meaningful advantage as per the first observation above.
### Part 1

To set up for dual-execution, the parties set up the OTs. Because we have a privacy-free step later, the Notary's OT needs to be opened up later, so we have the notary do a "committed OT" (see section 2 of [JKO13](https://eprint.iacr.org/2013/073)), so that he can be forced to open the labels later on.

In the first step of the protocol, the User has to get her AES ciphertext from the Notary. The User does not trust the Notary (for privacy or integrity), and the User's data is far more sensitive to leakage than the Notary's. So the parties do an ordinary DualEx:

0. The User and Notary both garble a copy of the encryption circuit, and do OTs for each other. For committed OT the Notary constructs the input wire labels and OT encryption keys as $\mathsf{PRG}(\rho)$ where $\rho$ is a randomly sampled PRG seed, and sends $\mathsf{com}_\rho$ to the User after the OT is done.
1. The User sends her garbled encryption circuit and garbled wires for $[k]\_1$ and $p$. She also sends the output decoding information.
2. The Notary uses his OT values to evaluate the circuit on $[k]\_2$. He derives the encoded ciphertext $C$ and decodes it into ciphertext $c$ using output decoding information.[^1]
3. The Notary sends $C$ to the User.[^2]

    Step 3 is a relaxation of DualEx. In DualEx, the User does not learn the Notary's evaluation output. As mentioned earlier, in TLSNotary protocol's setting, we are not worried that the User may leak the Notary's input, as long as this behaviour will be detected later. Also we are not worried about DualEx's inherent 1-bit leakage since it gives no meaningful advantage to the User as explained earlier. This means that in order to successfully attack this relaxation, a malicious User has to remain undetected during the DualEx equality check which will follow later in Step 14.

    The are 2 ways which come the closest to accomplishing the attack:

    A) The User must craft her circuit to output a fixed value $c'$. Then she must provide such inputs to the Notary's circuit that make the Notary's circuit output be $c'$.

    B) Upon learning $c$ (potentially containing the Notary's leaked inputs), the User will evaluate the Notary's circuit with her inputs changed, so that the evaluation result becomes $c$. 

    The attack A) is meaningless since it doesn't leak anything about the Notary's input. The attack B) is not possible because the User is locked into using the inputs she received in Step 0.

4. As per DualEx, now the Notary knows what the User's encoded output should be, so the Notary computes $Check_n = H(w_B || W_B^{v_B})$ and keeps it.
5. The User decodes $C$ and derives the ciphertext $c$.


[^1]: Note that it is in keeping with the original DualEx paper to allow a party to send the wrong output decoding information, or to provide different inputs to the two circuit evaluations. This does not result in a meaningful attack.

[^2]: A question may arise at this point re Step 3: why doesn't the Notary simply send $c$ to the User. The reason is that the Notary could send a maliciously crafted $c$: the Notary could flip a bit in $c$ (which translates into flipping a bit in the plaintext). The User would then forward the malicious $c$ to the server.


At this point, the Notary (even if malicious) has learned nothing about the key or the plaintext. He has only learned the ciphertext.

Also at this point, the User has learned the ciphertext, and, if malicious, has potentially learned the entire key $k$. As mentioned in the second observation above, it is okay if the User was malicious and learned $k$, but the Notary has to detect it and then abort the rest of the TLSNotary protocol. Before this step, the Notary waits for the User to complete their TLS session:

### Part 2

6. The User completes her TLS session and sends $\mathsf{com}\_\mathsf{resp}$

### Part 3

Now that the session is over and $[k]\_2$ is no longer secret, the Notary can switch to privacy-free garbling for the second part of DualEx.

7. The Notary sends his garbled encryption circuit to the User, as well as the garbled wires for $[k]\_2$. He also sends the output decoding information.
8. The User evaluates the circuit on $[k]\_1$ and $p$, using the OT values from step 0, derives the encoded ciphertext $C'$ and decodes it into ciphertext $c$ using output decoding information.
9. As per DualEx she computes $Check_u = H(w_A || W_A^{v_A})$ and sends a commitment $\mathsf{com}\_{Check_u}$ to the Notary.

    Note that at this stage the Notary could reveal $Check_n$ and the User would make sure that $Check_n == Check_u$. Then likewise the User would reveal $Check_u$ and the Notary would make sure that $Check_n == Check_u$.
    As per the DualEx's inherent 1-bit leakage, the very act of performing the equality check would leak 1 bit of the User's input to a malicious Notary. To avoid the leakage, the User must first check the consistency of the Notary's OT and garbled circuits:


10. The Notary reveals all the wire labels and OT encryption keys by opening $\mathsf{com}_\rho$.
11. The User checks that the opening is correct, and that $\mathsf{PRG}(\rho)$ is consistent with the wire labels and gates she received (this procedure is called $\mathsf{Ve}$ in [JKO13](https://eprint.iacr.org/2013/073)). On success, she opens her commitment, sending $C'$ and the commitment's randomness to the notary.

    With the consistency check passed, the parties resume the DualEx's equality check:

12. The Notary send $Check_n$.
13. The User asserts that $Check_n == Check_u$. The User decommits $\mathsf{com}\_{Check_u}$ by sending $Check_u$.
14. The Notary checks the decommitment and asserts that $Check_n == Check_u$.