## Motivation:

The purpose of this protocol is the same as `one side 2PC` https://github.com/tlsnotary/tlsn/blob/gcde_fix_leak/docs/gcde_leak_fix.md
except it uses the standard Dual Execution.

There is no need to explain as in `one side 2PC` why the User is able to send the wrong decoding and different plaintexts in both executions and yet the protocol is still sound.

This protocol is simpler to present and reason about.

This protocol works for server response decryption in multi-round TLS.

The downsides are:
 - not using privacy-free garbling raises the bandwidth cost from 300KB to 400KB per AES block.
 - the User must evaluate the circuit quickly while the TLS session is running (as opposed to after the TLS session in `one side 2PC`)



## Dual Execution with a delayed equality check.

### Part 1

1. The Notary constructs his garbled circuit from a seed `seed_gc`. The Notary also constructs his OT encryption keys from a seed `seed_ot`. The Notary sends a commitment `ComSeed(seed_gc | seed_ot; r)`, where r is random.

2. Acc.to the standard Dual Execution protocol as depicted in [Figure 1](https://www.cs.virginia.edu/~evans/pubs/oakland2012/quidproquotocols.pdf) each party sends the garbled circuit with the decoding information, receives their input labels via OT, evaluates the circuit, obtains the encoded output, decodes the output.

However the equality check is performed later after the User checks the consistency of the Notary's garbled circuit.

3. The User computes (see bottom of Figure 1) $H_u = H(W_A^{v_A} || w_A)$  and send a commitment $ComUser(H_u; r)$, where $r$ is random.

4. The Notary computes $H_n = H(w_B || W_B^{v_B})$ and keeps it.

5. The Notary sends his encoded outputs, i.e. he sends the output labels. 

6. The User decodes the output labels and derives $c$. 

### Part 2

7. The User completes her TLS session and sends a commitment to the server response.

### Part 3

8. The Notary opens `ComSeed` by revealing `seed_gc`, `seed_ot`, `r`.

9. The User checks `ComSeed`.

    The User reconstructs the input labels, the garbled circuit, and the output labels from `seed_gc` and checks that the garbled circuit matches the gabrled circuit she was evaluating in Step 2.

    The User re-constructs OT encryption keys from `seed_ot` and checks that the OT messages she received in Step 2 were the correct encryptions of the correct input labels.

Now that the User knows that Notary's wasn't malicious...

10. The User open `ComUser` by revealing $H_u$ and $r$.

11. The Notary checks `ComUser`.

    The notary asserts $H_u == H_n$.