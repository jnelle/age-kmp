use age_kmp::*;

#[test]
fn an_identity_yields_a_recipient_that_opens_what_it_sealed() {
    let identity = generate_identity();
    assert!(identity.starts_with("AGE-SECRET-KEY-1"));

    let recipient = identity_to_recipient(identity.clone()).unwrap();
    assert!(recipient.starts_with("age1"));

    let ciphertext = encrypt(b"Moin".to_vec(), vec![recipient]).unwrap();
    assert_eq!(decrypt(ciphertext, identity).unwrap(), b"Moin");
}

#[test]
fn every_recipient_can_open_a_multi_recipient_file() {
    let identities: Vec<String> = (0..4).map(|_| generate_identity()).collect();
    let recipients: Vec<String> = identities
        .iter()
        .map(|i| identity_to_recipient(i.clone()).unwrap())
        .collect();

    let ciphertext = encrypt(b"to all".to_vec(), recipients).unwrap();

    for identity in identities {
        assert_eq!(decrypt(ciphertext.clone(), identity).unwrap(), b"to all");
    }
}

#[test]
fn a_stranger_cannot_open_the_file() {
    let recipient = identity_to_recipient(generate_identity()).unwrap();
    let ciphertext = encrypt(b"secret".to_vec(), vec![recipient]).unwrap();

    assert!(decrypt(ciphertext, generate_identity()).is_err());
}

#[test]
fn the_ciphertext_is_a_binary_age_file() {
    let recipient = identity_to_recipient(generate_identity()).unwrap();

    let ciphertext = encrypt(b"Moin".to_vec(), vec![recipient]).unwrap();

    assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
    assert!(!ciphertext.windows(6).any(|w| w == b"Moin"));
}

#[test]
fn encrypting_to_nobody_is_refused() {
    assert!(matches!(
        encrypt(b"Moin".to_vec(), vec![]),
        Err(AgeError::NoRecipients)
    ));
}

#[test]
fn garbage_is_neither_an_identity_nor_a_recipient() {
    assert!(matches!(
        identity_to_recipient("not-a-key".into()),
        Err(AgeError::InvalidIdentity)
    ));
    assert!(matches!(
        encrypt(b"x".to_vec(), vec!["not-a-key".into()]),
        Err(AgeError::InvalidRecipient { .. })
    ));
    assert!(!is_valid_recipient("age1".into()));
    assert!(is_valid_recipient(
        identity_to_recipient(generate_identity()).unwrap()
    ));
}

#[test]
fn a_recovery_code_wraps_and_unwraps_an_identity() {
    let identity = generate_identity();
    let code = "correct-horse-battery-clippy";

    let blob = encrypt_with_passphrase(identity.as_bytes().to_vec(), code.into(), 10).unwrap();
    let restored = decrypt_with_passphrase(blob.clone(), code.into(), 20).unwrap();

    assert_eq!(String::from_utf8(restored).unwrap(), identity);
    assert!(decrypt_with_passphrase(blob, "wrong-code".into(), 20).is_err());
}

#[test]
fn a_work_factor_above_the_cap_is_refused() {
    let blob = encrypt_with_passphrase(b"x".to_vec(), "code".into(), 12).unwrap();

    assert!(decrypt_with_passphrase(blob, "code".into(), 10).is_err());
}

#[test]
fn surrounding_whitespace_is_tolerated() {
    let identity = generate_identity();
    let recipient = identity_to_recipient(format!("  {identity}\n")).unwrap();

    let ciphertext = encrypt(b"Moin".to_vec(), vec![format!(" {recipient} ")]).unwrap();

    assert_eq!(
        decrypt(ciphertext, format!("\t{identity}")).unwrap(),
        b"Moin"
    );
}

fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("age-kmp-{}-{name}", std::process::id()))
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn a_file_round_trips_through_the_streaming_api() {
    let identity = generate_identity();
    let recipient = identity_to_recipient(identity.clone()).unwrap();
    let plain = scratch("in.bin");
    let sealed = scratch("in.age");
    let opened = scratch("out.bin");
    let payload = pattern(5 * 1024 * 1024);
    std::fs::write(&plain, &payload).unwrap();

    let consumed = encrypt_file(
        plain.to_string_lossy().into(),
        sealed.to_string_lossy().into(),
        vec![recipient],
    )
    .unwrap();
    let ciphertext = std::fs::read(&sealed).unwrap();
    let written = decrypt_file(
        sealed.to_string_lossy().into(),
        opened.to_string_lossy().into(),
        identity,
    )
    .unwrap();

    assert_eq!(consumed, payload.len() as u64);
    assert_eq!(written, payload.len() as u64);
    assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
    assert!(ciphertext.len() > payload.len());
    assert_eq!(std::fs::read(&opened).unwrap(), payload);

    for path in [plain, sealed, opened] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn a_stranger_cannot_open_the_file_stream() {
    let recipient = identity_to_recipient(generate_identity()).unwrap();
    let plain = scratch("stranger-in.bin");
    let sealed = scratch("stranger.age");
    let opened = scratch("stranger-out.bin");
    std::fs::write(&plain, b"secret").unwrap();
    encrypt_file(
        plain.to_string_lossy().into(),
        sealed.to_string_lossy().into(),
        vec![recipient],
    )
    .unwrap();

    let result = decrypt_file(
        sealed.to_string_lossy().into(),
        opened.to_string_lossy().into(),
        generate_identity(),
    );

    assert!(matches!(result, Err(AgeError::Decrypt)));
    for path in [plain, sealed, opened] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn a_missing_input_file_is_an_io_error() {
    let recipient = identity_to_recipient(generate_identity()).unwrap();

    let result = encrypt_file(
        scratch("does-not-exist.bin").to_string_lossy().into(),
        scratch("never-written.age").to_string_lossy().into(),
        vec![recipient],
    );

    assert!(matches!(result, Err(AgeError::Io { .. })));
}
