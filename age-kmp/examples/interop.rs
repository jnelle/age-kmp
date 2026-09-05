use std::env;
use std::fs;

fn main() {
    let dir = env::args().nth(1).expect("usage: interop <dir>");
    let step = env::args().nth(2).unwrap_or_else(|| "seal".into());

    match step.as_str() {
        "seal" => {
            let identity = age_kmp::generate_identity();
            let recipient = age_kmp::identity_to_recipient(identity.clone()).unwrap();
            fs::write(format!("{dir}/identity.txt"), &identity).unwrap();
            fs::write(format!("{dir}/recipient.txt"), &recipient).unwrap();

            let ciphertext =
                age_kmp::encrypt(b"vom Rust-Client".to_vec(), vec![recipient]).unwrap();
            fs::write(format!("{dir}/from-rust.age"), ciphertext).unwrap();
            println!("sealed");
        }
        "open" => {
            let identity = fs::read_to_string(format!("{dir}/identity.txt")).unwrap();
            let ciphertext = fs::read(format!("{dir}/from-go.age")).unwrap();
            let plaintext = age_kmp::decrypt(ciphertext, identity).unwrap();
            println!("{}", String::from_utf8(plaintext).unwrap());
        }
        other => panic!("unknown step {other}"),
    }
}
