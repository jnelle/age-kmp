//! age for Kotlin Multiplatform.
//!
//! A thin UniFFI surface over the reference Rust implementation of the
//! [age](https://age-encryption.org/v1) file encryption format. Everything here
//! is a plain function over bytes and strings: keeping state on the Kotlin side
//! avoids handing out object handles that callers have to remember to free.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AgeError {
    #[error("invalid age identity")]
    InvalidIdentity,
    #[error("invalid age recipient: {reason}")]
    InvalidRecipient { reason: String },
    #[error("no recipients")]
    NoRecipients,
    #[error("encryption failed: {reason}")]
    Encrypt { reason: String },
    #[error("decryption failed")]
    Decrypt,
    #[error("the file demands more scrypt work than permitted")]
    ExcessiveWork,
    #[error("read failed: {reason}")]
    Read { reason: String },
    #[error("file access failed: {reason}")]
    Io { reason: String },
}

#[uniffi::export]
pub fn generate_identity() -> String {
    x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_owned()
}

#[uniffi::export]
pub fn identity_to_recipient(identity: String) -> Result<String, AgeError> {
    Ok(parse_identity(&identity)?.to_public().to_string())
}

#[uniffi::export]
pub fn is_valid_recipient(recipient: String) -> bool {
    recipient.trim().parse::<x25519::Recipient>().is_ok()
}

#[uniffi::export]
pub fn encrypt(plaintext: Vec<u8>, recipients: Vec<String>) -> Result<Vec<u8>, AgeError> {
    seal(encryptor_for(&recipients)?, &plaintext)
}

/// Seals the file at `input_path` into a binary age file at `output_path`, in age's 64 KiB
/// chunks, so neither side is ever held in memory. Returns the number of plaintext bytes
/// consumed. `output_path` is created or truncated; on an error it may hold a partial file, which
/// the caller removes.
#[uniffi::export]
pub fn encrypt_file(
    input_path: String,
    output_path: String,
    recipients: Vec<String>,
) -> Result<u64, AgeError> {
    let encryptor = encryptor_for(&recipients)?;
    let mut input = BufReader::new(File::open(&input_path).map_err(io_error)?);
    let output = BufWriter::new(File::create(&output_path).map_err(io_error)?);

    let mut writer = encryptor.wrap_output(output).map_err(encrypt_error)?;
    let consumed = std::io::copy(&mut input, &mut writer).map_err(encrypt_error)?;
    let mut output = writer.finish().map_err(encrypt_error)?;
    output.flush().map_err(io_error)?;

    Ok(consumed)
}

/// Opens the age file at `input_path` into `output_path`, streaming. Returns the plaintext bytes
/// written. `Decrypt` means the file is not addressed to `identity` or its header is malformed;
/// `Read` means the payload failed authentication mid-stream, leaving a partial output for the
/// caller to remove.
#[uniffi::export]
pub fn decrypt_file(
    input_path: String,
    output_path: String,
    identity: String,
) -> Result<u64, AgeError> {
    let identity = parse_identity(&identity)?;
    let input = BufReader::new(File::open(&input_path).map_err(io_error)?);
    let decryptor = age::Decryptor::new_buffered(input).map_err(decrypt_error)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(decrypt_error)?;

    let mut output = BufWriter::new(File::create(&output_path).map_err(io_error)?);
    let written = std::io::copy(&mut reader, &mut output).map_err(|err| AgeError::Read {
        reason: err.to_string(),
    })?;
    output.flush().map_err(io_error)?;

    Ok(written)
}

#[uniffi::export]
pub fn decrypt(ciphertext: Vec<u8>, identity: String) -> Result<Vec<u8>, AgeError> {
    let identity = parse_identity(&identity)?;
    let decryptor = age::Decryptor::new(&ciphertext[..]).map_err(decrypt_error)?;

    open(decryptor, std::iter::once(&identity as &dyn age::Identity))
}

#[uniffi::export]
pub fn encrypt_with_passphrase(
    plaintext: Vec<u8>,
    passphrase: String,
    work_factor: u8,
) -> Result<Vec<u8>, AgeError> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase));
    recipient.set_work_factor(work_factor);

    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(encrypt_error)?;

    seal(encryptor, &plaintext)
}

#[uniffi::export]
pub fn decrypt_with_passphrase(
    ciphertext: Vec<u8>,
    passphrase: String,
    max_work_factor: u8,
) -> Result<Vec<u8>, AgeError> {
    let mut identity = age::scrypt::Identity::new(SecretString::from(passphrase));
    identity.set_max_work_factor(max_work_factor);

    let decryptor = age::Decryptor::new(&ciphertext[..]).map_err(decrypt_error)?;

    open(decryptor, std::iter::once(&identity as &dyn age::Identity))
}

/// Shared by `encrypt` and `encrypt_file`: parses every recipient or refuses the lot.
fn encryptor_for(recipients: &[String]) -> Result<age::Encryptor, AgeError> {
    if recipients.is_empty() {
        return Err(AgeError::NoRecipients);
    }

    let parsed = recipients
        .iter()
        .map(|recipient| {
            recipient
                .trim()
                .parse::<x25519::Recipient>()
                .map_err(|err| AgeError::InvalidRecipient {
                    reason: err.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let refs: Vec<&dyn age::Recipient> = parsed.iter().map(|r| r as &dyn age::Recipient).collect();
    age::Encryptor::with_recipients(refs.into_iter()).map_err(encrypt_error)
}

fn io_error(err: std::io::Error) -> AgeError {
    AgeError::Io {
        reason: err.to_string(),
    }
}

fn parse_identity(identity: &str) -> Result<x25519::Identity, AgeError> {
    identity
        .trim()
        .parse::<x25519::Identity>()
        .map_err(|_| AgeError::InvalidIdentity)
}

fn seal(encryptor: age::Encryptor, plaintext: &[u8]) -> Result<Vec<u8>, AgeError> {
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).map_err(encrypt_error)?;
    writer.write_all(plaintext).map_err(encrypt_error)?;
    writer.finish().map_err(encrypt_error)?;

    Ok(out)
}

fn open<'a, R: Read>(
    decryptor: age::Decryptor<R>,
    identities: impl Iterator<Item = &'a dyn age::Identity>,
) -> Result<Vec<u8>, AgeError> {
    let mut reader = decryptor.decrypt(identities).map_err(decrypt_error)?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out).map_err(|err| AgeError::Read {
        reason: err.to_string(),
    })?;

    Ok(out)
}

fn encrypt_error(err: impl std::fmt::Display) -> AgeError {
    AgeError::Encrypt {
        reason: err.to_string(),
    }
}

fn decrypt_error(err: age::DecryptError) -> AgeError {
    match err {
        age::DecryptError::ExcessiveWork { .. } => AgeError::ExcessiveWork,
        _ => AgeError::Decrypt,
    }
}
