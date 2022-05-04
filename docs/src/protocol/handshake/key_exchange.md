# Key Exchange

In TLS, the first step towards obtaining TLS session keys is to compute a shared secret between the client and the server by running the [ECDH protocol](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman). The resulting shared secret in TLS terms is called the pre-master secret `PMS`.

Using the notation from Wikipedia, below is the 3-party ECDH protocol between the `Server` the `Client` and the `Notary`, enabling the `Client` and the `Notary` to arrive at shares of `PMS`.


1. `Server` sends its public key \\(\small{Q_b}\\) to `Client`, and `Client` forwards it to `Notary`
2. `Client` picks a random private key share \\( \small{d_c} \\) and computes a public key share \\( \small{Q_c = d_c * G} \\)
3. `Notary` picks a random private key share \\( \small{d_n} \\) and computes a public key share \\( \small{Q_n = d_n * G} \\)
4. `Notary` sends \\( \small{Q_n} \\) to `Client` who computes \\( \small{Q_a = Q_c + Q_n} \\) and sends \\( \small{Q_a} \\) to `Server`
5. `Client` computes an EC point \\( \small{(x_p, y_p) = d_c * Q_b} \\)
6. `Notary` computes an EC point \\( \small{(x_q, y_q) = d_n * Q_b} \\)
7. Addition of points \\( \small{(x_p, y_p)} \\) and \\( \small{(x_q, y_q)} \\) results in the coordinate \\( \small{x_r} \\), which is `PMS`. (The coordinate \\( \small{y_r} \\) is not used in TLS)


Using the notation from [here](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition), our goal is to compute
\\[ \tag{1} x_r = (\frac{y_q-y_p}{x_q-x_p})^2 - x_p - x_q \\]
in such a way that
1. Neither party learns the other party's \\( \small{x} \\) value
2. Neither party learns \\( \small{x_r} \\), only their respective shares of \\( \small{x_r} \\).

Let's start out by simplifying the equation

\\[\tag{2} x_r = (y_q^2 - 2y_q y_p + y_p^2)(x_q - x_p)^{-2} - x_p - x_q \bmod p \\]

Since this is finite field arithmetic, if \\( \small{x_r > p} \\) we must reduce \\( \small{x_r} \\) modulo \\( \small{p} \\), i.e assign \\( \small{x_r} \\) the value \\( \small{x_r \bmod p} \\). The trailing \\( \small{\bmod p} \\) is always implied from here on out, but may be omitted for brevity.

> For the curious, the modulus of the most common EC curve P-256 is a prime number and its value is \\( \small{p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1}\\)

Based on [Fermat's little theorem](https://en.wikipedia.org/wiki/Fermat's_little_theorem):

\\[ a^{-2} \bmod p = a^{p-3} \bmod p \\]

Replacing the negative power of Equation (2), we get:

\\[\tag{3} x_r = (y_q^2 - 2y_q y_p + y_p^2)(x_q - x_p)^\color{red}{p-3} - x_p - x_q \\]

We then proceed to decompose Equation (3) into discrete parts:

\\[ \tag{4} A = (y_q^2 - 2y_q y_p + y_p^2) \\\\\\
B = (x_q - x_p)^{p-3} \\\\\\
C = - x_p - x_q \\]

## Computing \\( \small{A = (y_q^2 - 2y_q y_p + y_p^2)} \\)

`Notary`:

1. Sends \\( \small{E(y_q^2)} \\) and \\( \small{E(-2y_q)} \\)

`Client`:

2. Computes \\( \small{E(y_p^2)} \\)
3. Computes \\( \small{E(A) = E(y_q^2) + E(-2y_q) * y_p + E(y_p^2)} \\)
4. Generates random masks \\( \small{M_A} \\) and \\( \small{N_A} \\) and computes \\( \small{E(A * M_A + N_A)} \\)
5. Sends \\( \small{E(A * M_A + N_A)} \\) and \\( \small{(N_A \bmod p)} \\)

> Note that here \\( \small{N_A} \\) (as well as \\( \small{N_b} \\) and \\( \small{N_B} \\) below) is crucial, as without it `Notary` would be able to factorize \\( \small{A * M_A} \\) and learn \\( \small{A} \\)

`Notary`:

6. Decrypts and gets \\( \small{(A * M_A + N_A)} \\)
7. Reduces \\( \small{(A * M_A + N_A) \bmod p} \\)
8. Computes \\( \small{(A * M_A) \bmod p = (A * M_A + N_A) \bmod p - N_A \bmod p} \\)

## Computing \\( \small{B = (x_q - x_p)^{p-3}} \\)

`Notary`:

1. Sends \\( \small{E(x_q)} \\)

`Client`:

2. Lets \\( \small{b = x_q - x_p} \\)
3. Computes \\( \small{E(-x_p)} \\)
4. Computes \\( \small{E(b) = E(x_q) + E(-x_p)} \\)
5. Generates random masks \\( \small{M_b} \\) and \\( \small{N_b} \\) and computes \\( \small{E(b * M_b + N_b)} \\)
6. Sends \\( \small{E(b * M_b + N_b)} \\) and \\( \small{(N_b \bmod p)} \\)

`Notary`:

7. Decrypts and gets \\( \small{(b * M_b + N_b)} \\)
8. Reduces \\( \small{(b * M_b + N_b) \bmod p} \\)
9. Computes \\( \small{(b * M_b) \bmod p = (b * M_b + N_b) \bmod p - N_b \bmod p} \\)
10. Sends \\( \small{E((b * M_b)^{p-3} \bmod p)} \\)

`Client`:

11.  Computes multiplicative inverse \\( \small{inv = (M_b^{p-3})^{-1} \bmod p} \\)
12.  Computes \\( \small{E((b * M_b)^{p-3} \bmod p) * inv = E(b^{p-3} * (M_b^{p-3})^{-1}) = E(b^{p-3}) = E(B)} \\)
13.  Generates random masks \\( \small{M_B} \\) and \\( \small{N_B)} \\) and computes \\( \small{E(B * M_B + N_B)} \\)
14.  Sends \\( \small{E(B * M_B + N_B)} \\) and \\( \small{N_B \bmod p} \\)

`Notary`:

15. Decrypts and gets \\( \small{(B * M_B + N_B)} \\)
16. Reduces \\( \small{(B * M_B + N_B) \bmod p} \\)
17. Computes \\( \small{(B * M_B) \bmod p = (B * M_B + N_B) \bmod p - N_B \bmod p} \\)

## Computing \\( \small{x_r = A * B + C} \\)

`Notary`:

1. Sends \\( \small{E(A * M_A * B * M_B)} \\) and \\( \small{E(-x_q)} \\)

`Client`:

2. Computes \\( \small{E(A * B) = E(A * M_A * B * M_B) * (M_A * M_B)^{-1}} \\) and \\( \small{E(-x_p)} \\)
3. Computes \\( \small{E(A * B + C) = E(A * B) + E(-x_q) + E(-x_p)} \\)
4. Generates and applies a random mask \\( \small{E(S_q)} \\) and sends \\( \small{E(A * B + C + S_q)} \\)
5. Computes additive `PMS` share \\( \small{s_q = (S_q \bmod p)} \\)

`Notary`:

6. Decrypts and gets \\( \small{A * B + C + S_q} \\)
7. Computes additive `PMS` share \\( \small{s_p = (A * B + C + S_q) \bmod p} \\)

The protocol described above is secure against `Notary` sending malicious inputs. Indeed, because `Client` only sends back masked values, `Notary` cannot learn anything about those values.