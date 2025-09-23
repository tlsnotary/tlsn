use dep::date::Date;

fn main(
    // Public inputs
    proof_date: pub date::Date, // "2025-08-29"
    committed_hash: pub [u8; 32], // Hash of (blinder || dob string)
    // Private inputs
    date_of_birth: str<10>, // "1985-03-12"
    blinder: [u8; 16], // Random 16-byte blinder
) {
    let is_18 = check_18(date_of_birth, proof_date);

    let correct_hash = check_hash(date_of_birth, blinder, committed_hash);

    assert(correct_hash);
    assert(is_18);
}

fn check_18(date_of_birth: str<10>, proof_date: date::Date) -> bool {
    let dob = parse_birth_date(date_of_birth);
    let is_18 = dob.add_years(18).lt(proof_date);
    println(f"Is 18? {is_18}");
    is_18
}

fn check_hash(date_of_birth: str<10>, blinder: [u8; 16], committed_hash: [u8; 32]) -> bool {
    let hash_input: [u8; 26] = make_hash_input(date_of_birth, blinder);
    let computed_hash = sha256::sha256_var(hash_input, 26);
    let correct_hash = computed_hash == committed_hash;
    println(f"Correct hash? {correct_hash}");
    correct_hash
}

fn make_hash_input(dob: str<10>, blinder: [u8; 16]) -> [u8; 26] {
    let mut input: [u8; 26] = [0; 26];
    for i in 0..10 {
        input[i] = dob.as_bytes()[i];
    }
    for i in 0..16 {
        input[10 + i] = blinder[i];
    }
    input
}

pub fn parse_birth_date(birth_date: str<10>) -> date::Date {
    let date: [u8; 10] = birth_date.as_bytes();
    let date_str: str<8> =
        [date[0], date[1], date[2], date[3], date[5], date[6], date[8], date[9]].as_str_unchecked();
    Date::from_str_long_year(date_str)
}

#[test]
fn test_max_is_over_18() {
    // Private input
    let date_of_birth = "1985-03-12";
    let blinder = [120, 80, 62, 10, 76, 60, 130, 98, 147, 161, 139, 126, 27, 236, 36, 56];

    // Public input
    let proof_date = date::Date { year: 2025, month: 9, day: 2 };
    let committed_hash = [
        229, 118, 202, 216, 213, 230, 125, 163, 48, 178, 118, 225, 84, 7, 140, 63, 173, 255, 163,
        208, 163, 3, 63, 204, 37, 120, 254, 246, 202, 116, 122, 145,
    ];

    main(proof_date, committed_hash, date_of_birth, blinder);
}

#[test(should_fail)]
fn test_under_18() {
    // Private input
    let date_of_birth = "2010-08-01";
    let blinder = [160, 23, 57, 158, 141, 195, 155, 132, 109, 242, 48, 220, 70, 217, 229, 189];

    // Public input
    let proof_date = date::Date { year: 2025, month: 8, day: 29 };
    let committed_hash = [
        16, 132, 194, 62, 232, 90, 157, 153, 4, 231, 1, 54, 226, 3, 87, 174, 129, 177, 80, 69, 37,
        222, 209, 91, 168, 156, 9, 109, 108, 144, 168, 109,
    ];

    main(proof_date, committed_hash, date_of_birth, blinder);
}
