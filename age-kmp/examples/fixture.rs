fn main() {
    let out = std::env::args().nth(1).expect("usage: fixture <path>");
    let recipients: Vec<String> = (0..3)
        .map(|_| age_kmp::identity_to_recipient(age_kmp::generate_identity()).unwrap())
        .collect();
    let ciphertext =
        age_kmp::encrypt("Moin from Rust 💪".as_bytes().to_vec(), recipients).unwrap();
    std::fs::write(out, ciphertext).unwrap();
}
