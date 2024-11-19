use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;

use poseidon_circomlib::{hash, F};

lazy_static! {
    /// Test vectors from
    /// https://github.com/iden3/circomlibjs/blob/ad7627a4c00733e5e59e83ad2ebcc70b1fecb613/test/poseidon.js
    static ref TEST_VECTORS: [(Vec<u8>, BigUint); 7] = [
        (
            vec![1, 2],
            BigUint::from_str_radix(
                "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
                16,
            )
            .unwrap(),
        ),
        (
            vec![1, 2, 3, 4],
            BigUint::from_str_radix(
                "299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
                16,
            )
            .unwrap(),
        ),
        (
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            BigUint::from_str_radix(
                "9989051620750914585850546081941653841776809718687451684622678807385399211877",
                10,
            )
            .unwrap(),
        ),
        (
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0],
            BigUint::from_str_radix(
                "11882816200654282475720830292386643970958445617880627439994635298904836126497",
                10,
            )
            .unwrap(),
        ),
        (
            vec![1, 2, 3, 4, 5, 6],
            BigUint::from_str_radix(
                "20400040500897583745843009878988256314335038853985262692600694741116813247201",
                10,
            )
            .unwrap(),
        ),
        (
            vec![1],
            BigUint::from_str_radix(
                "18586133768512220936620570745912940619677854269274689475585506675881198879027",
                10,
            )
            .unwrap(),
        ),
        (
            vec![1, 2, 0, 0, 0],
            BigUint::from_str_radix(
                "1018317224307729531995786483840663576608797660851238720571059489595066344487",
                10,
            )
            .unwrap(),
        ),
    ];
}

/// Tests the hash output against test vectors.
#[test]
fn test_output() {
    for (input, expected_output) in TEST_VECTORS.iter() {
        let input = input.iter().map(u8_to_field).collect::<Vec<_>>();
        assert_eq!(hash(&input), biguint_to_field(expected_output));
    }
}

fn u8_to_field(byte: &u8) -> F {
    let mut bytes = [0u8; 32];
    bytes[0..1].copy_from_slice(&[*byte]);
    F::from_bytes(&bytes).unwrap()
}

fn biguint_to_field(buint: &BigUint) -> F {
    let buint = buint.to_bytes_le();
    let mut bytes = [0u8; 32];
    bytes[0..buint.len()].copy_from_slice(&buint);
    F::from_bytes(&bytes).unwrap()
}
