## Background

The User wants to encrypt a TLS request with some server, but she doesn't have the encryption key. Rather she has just one share of the key. The Notary has the other share. The Notary needs to know that the only ciphertext sent to the TLS server is the ciphertext he has seen (it would be bad, e.g., if the User had the full key because she'd lie to the Notary about the request she sent). We want a 2PC scheme that will allow the User and Notary to collaboratively compute the ciphertext such that: the User does not reveal her plaintext or key share, and the Notary does not reveal his key share.

## Idea

We make two observations. Firstly, a small amount of keyshare leakage is tolerable. E.g., if the Notary leaks 3 bits of their keyshare, it gives the User no meaningful advantage in any attack, as she could have simply guessed the bits correctly with ($1/2^3$) 12.5% probability and mounted the same attack.

Secondly, we observe that the Notary's keyshare is an _ephemeral secret_: it is only private for the duration of the User's TLS session. This implies two things:

1. The User is free to learn the encryption key after she has received and committed to the TLS response. Thus, if the parties wait until the end of the TLS session to do maliciousness checks, then they can reap the benefits of the Notary having no private inputs.
2. Since the encryption key is not a long-term secret, it is okay if a malicious User prematurely learns the entire key, _so long as it is detected_. Thus, the parties are free to engage in potentially leaky MPC early on, so long as checks are performed at some point.

## Prelims

* $p$ is the User's plaintext request
* $k$ is the AES key
* $[k]\_1$ and $[k]\_2$ are the User's and Notary's AES keyshares, respectively. That is, $k = [k]\_1 \oplus [k]\_2$.
* $\mathsf{Enc}$ denotes the encryption algorithm used by the TLS session
* $\mathsf{Com}(x; r)$ denotes a binding commitment to $x$ with randomness $r$

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

We now describe the protocol at a high level. Broadly, it has the structure of the [Dual-Execution technique](https://www.cs.virginia.edu/~evans/pubs/oakland2012/quidproquotocols.pdf), but with some relaxations.

### Part 1

To set up for dual-execution, the parties set up the OTs. In the first step of the protocol, the User has to get her ciphertext from the Notary. The User does not trust the Notary (for privacy or integrity), and the User's data is far more sensitive to leakage than the Notary's. So the parties do an ordinary MPC:

0. The User and Notary both garble a copy of the encryption circuit, and do OTs for each other.
1. The User sends her garbled encryption circuit and garbled wires for $[k]\_1$ and $p$. She _does not_ send the output decoding information.
2. The Notary uses his OT values to evaluate the circuit on $[k]\_2$. He derives the encoded ciphertext $C$, and sends it to the User
3. The User uses her decoding information to derive the ciphertext $c$ from the Notary. She sends $c$ to the Notary.

//--------------

Footnote:

A question may arise at this point re Steps 2 and 3: why doesn't the User simply reveal the decoding information to the Notary, so that the Notary himself would be able to decode the ciphertext $C$ and send $c$ to the User. 

The reason is that after the decoding the Notary could send to the User a malicious $c$, e.g. the Notary could flip a bit in $c$ (which translates into flipping a bit in the plaintext). The User would then forward the malicious $c$ to the server. 

//--------------

At this point, the Notary (even if malicious) has learned nothing about the key, the ciphertext, or the plaintext.

Also at this point, the User has learned the ciphertext, and, if malicious, has potentially learned the entire key $k$. As mentioned in the second observation above, it is okay if the User was malicious and learned $k$, but the Notary has to detect it and then abort the rest of the TLSNotary protocol. Before this step, the Notary waits for the User to complete their TLS session:

### Part 2

4. The User completes her TLS session and sends $\mathsf{com}\_\mathsf{resp} := \mathsf{Com}(\mathsf{resp}; r)$

### Part 3

Now that the session is over and $[k]\_2$ is no longer secret, the Notary begins the maliciousness check. Taking a page out of the Dual-Execution method, the Notary will check that the User can derive the same ciphertext, given the full key. If she can, then this proves that the User knew a $p$ and $[k]\_1$ before the protocol started such that  $\mathsf{Enc}\_k(p) = c$. This proves that the derivation of $c$ in Part 1 was performed honestly, and nothing was prematurely leaked to the User.

To do this check, the Notary will do a privacy-free garbling to compute $\mathsf{Enc}\_k(p)$ where $k$ and $p$ are known only to the User:

5. The Notary sends his garbled encryption circuit to the User, as well as the garbled wires for $[k]\_2$. He _does not_ send the decoding information to the User.
6. The User evaluates the circuit on $[k]\_1$ and $p$, using the OT values from step 0. The result is the encoded ciphertext $C'$, which the User commits to as $\mathsf{com}\_{C'} := \mathsf{Com}(C'; r')$ for some randomness $r'$. She then sends $\mathsf{com}\_{C'}$ to the Notary.
7. The Notary opens the garbled circuit to the User, revealing all the wire labels (this can be done, e.g., by sending a PRG seed ρ that was used to generate the wire labels).
8. The User checks that the opening is well-formed, consistent with the wire labels and gates she received earlier. On success, she opens her commitment, sending $C'$ and $r'$ to the Notary.
9. The Notary checks the commitment opening and decodes $C'$ to ciphertext $c'$. Finally the Notary verifies that $c == c'$. On success, the Notary outputs success.

To recap, the Notary forced the User to produce the ciphertext $c'$ herself, and then checked that it was equal to the ciphertext he saw earlier. If this is the case, then nothing prematurely leaked to the User. Also note: this part could have only happened after the TLS session was over, because step 7 reveals $k$ to the User.