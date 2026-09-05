# age-kmp

[age](https://age-encryption.org/v1) file encryption for Kotlin Multiplatform,
backed by the [Rust reference implementation](https://crates.io/crates/age)
through [UniFFI](https://mozilla.github.io/uniffi-rs/) and
[Gobley](https://github.com/gobley/gobley).

One Rust core serves every target, so an Android phone, an iPhone and a JVM test
run produce byte-identical files — and so do the Go, Rust and TypeScript
implementations on the other end of the wire.

## Targets

| Target | Notes |
|---|---|
| `androidTarget` | minSdk 26 |
| `iosArm64` | device |
| `iosSimulatorArm64` | simulator on Apple Silicon, also where the tests run |

`iosX64` (the Intel-Mac simulator) is not supported. Neither is `jvm` at the moment.


## Install

```kotlin
dependencies {
    implementation("io.github.jnelle:age-kmp:0.2.0")
}
```

## Usage

```kotlin
import io.github.jnelle.agekmp.*

// On first start: generate an identity and keep it in the Keystore/Keychain.
val identity = generateIdentity()          // "AGE-SECRET-KEY-1…"
val recipient = identityToRecipient(identity)  // "age1…"  — this is what you publish

// Encrypt to everyone who should be able to read it.
val ciphertext = encrypt(
    plaintext = "Moin".encodeToByteArray(),
    recipients = listOf(recipient, someoneElsesRecipient),
)

// Decrypt with your own identity.
val plaintext = decrypt(ciphertext, identity).decodeToString()
```

### Recovery

An identity that only exists on one device is one lost phone away from an
unreadable history. Wrap it under a recovery code with age's scrypt recipient and
store the result wherever you like — it is useless without the code.

```kotlin
val code = "correct-horse-battery-clippy"

val blob = encryptWithPassphrase(identity.encodeToByteArray(), code, workFactor = 18u)
// …later, on a new device:
val restored = decryptWithPassphrase(blob, code, maxWorkFactor = 20u).decodeToString()
```

`workFactor` is the base-two logarithm of the scrypt cost. 18 is a reasonable
default for a high-entropy recovery code; higher values cost real seconds on a
phone. `maxWorkFactor` caps how much work a hostile blob can demand before it is
rejected.

## API

Every function throws `AgeException` on failure.

| Function | Returns |
|---|---|
| `generateIdentity()` | `String` — `AGE-SECRET-KEY-1…` |
| `identityToRecipient(identity: String)` | `String` — `age1…` |
| `isValidRecipient(recipient: String)` | `Boolean`, without encrypting |
| `encrypt(plaintext: ByteArray, recipients: List<String>)` | `ByteArray` — a binary age file |
| `decrypt(ciphertext: ByteArray, identity: String)` | `ByteArray` |
| `encryptWithPassphrase(plaintext: ByteArray, passphrase: String, workFactor: UByte)` | `ByteArray` |
| `decryptWithPassphrase(ciphertext: ByteArray, passphrase: String, maxWorkFactor: UByte)` | `ByteArray` |
| `encryptFile(inputPath: String, outputPath: String, recipients: List<String>)` | `ULong` — plaintext bytes consumed; writes a binary age file |
| `decryptFile(inputPath: String, outputPath: String, identity: String)` | `ULong` — plaintext bytes written |

Leading and trailing whitespace on identities and recipients is tolerated, so a
value pasted from a text field or scanned from a QR code works as-is.

### Files

`encryptFile` and `decryptFile` stream through age's 64 KiB chunks, so a video is never held in
memory. They block the calling thread for as long as the file takes -- call them off the main
thread. On an error the output path may hold a partial file; remove it. `AgeException.Io` reports
a path that could not be opened or written.

### What this library does not do

- **No key storage.** Where the identity lives — Android Keystore, iOS Keychain,
  IndexedDB — is the application's decision, and platform-specific.
- **No armored output.** Files are binary. Base64 them yourself if a transport
  needs text.
- **No sender authentication.** age proves nothing about who wrote a file; anyone
  holding the recipients can produce a valid one. If that matters, sign the
  ciphertext separately.
- **No forward secrecy.** Whoever obtains an identity can read every file ever
  addressed to it.

## Failure modes worth knowing

`decrypt` does not distinguish "not addressed to you" from "malformed", and
carries no message from the underlying library. That is deliberate twice over:
the distinction leaks whether a file was meant for the caller, and `age` 0.12.1
panics with an integer overflow while formatting `DecryptError::ExcessiveWork`
(`src/error.rs:380`), so attacker-controlled input must never reach that
`Display` implementation. `ExcessiveWork` is surfaced as its own error variant
instead.

## Building

```bash
# The Rust core — this is the part that carries the cryptography.
cd age-kmp && cargo test

# The Kotlin API, exercised on the iOS simulator.
./gradlew :age-kmp:iosSimulatorArm64Test

# Android AAR and iOS klibs.
./gradlew assemble
```

The full build needs macOS for the Apple targets, plus the Android SDK **and
NDK 30.0.16138531** — the version is pinned in `gradle/libs.versions.toml`.
Install it through Android Studio under *Settings → Languages & Frameworks →
Android SDK → SDK Tools → NDK (Side by side)*, or with
`sdkmanager --install "ndk;30.0.16138531"`. Without it the Rust cross-compile
fails with `linker aarch64-linux-android26-clang not found`.

Rust targets needed for a full build:

```bash
rustup target add \
  aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android \
  aarch64-apple-ios aarch64-apple-ios-sim
```

## Interoperability

`age-kmp/examples/interop.rs` seals a file this library can be checked against
from another implementation, and opens one produced elsewhere. It is how the
cross-implementation fixture used by the Go backend was generated:

```bash
cargo run --example fixture -- /path/to/three-recipients.age
```

Note for anyone writing the other end: the Rust implementation emits a random
**grease** stanza (`-> |N-grease …`) in every header on purpose. The spec requires
unknown stanzas to be ignored, and a parser that rejects them will reject every
file this library produces.

## License

Apache-2.0.
