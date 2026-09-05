package io.github.jnelle.agekmp

import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.readByteArray
import kotlinx.io.write
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AgeTest {

    @Test
    fun anIdentityYieldsARecipientThatOpensWhatItSealed() {
        val identity = generateIdentity()
        assertTrue(identity.startsWith("AGE-SECRET-KEY-1"))

        val recipient = identityToRecipient(identity)
        assertTrue(recipient.startsWith("age1"))

        val ciphertext = encrypt("Moin".encodeToByteArray(), listOf(recipient))
        assertEquals("Moin", decrypt(ciphertext, identity).decodeToString())
    }

    @Test
    fun everyRecipientCanOpenAMultiRecipientFile() {
        val identities = List(4) { generateIdentity() }
        val recipients = identities.map { identityToRecipient(it) }

        val ciphertext = encrypt("to all".encodeToByteArray(), recipients)

        for (identity in identities) {
            assertEquals("to all", decrypt(ciphertext, identity).decodeToString())
        }
    }

    @Test
    fun aStrangerCannotOpenTheFile() {
        val recipient = identityToRecipient(generateIdentity())
        val ciphertext = encrypt("secret".encodeToByteArray(), listOf(recipient))

        assertFailsWith<AgeException> { decrypt(ciphertext, generateIdentity()) }
    }

    @Test
    fun theCiphertextIsABinaryAgeFile() {
        val recipient = identityToRecipient(generateIdentity())

        val ciphertext = encrypt("Moin".encodeToByteArray(), listOf(recipient))

        assertTrue(ciphertext.decodeToString().startsWith("age-encryption.org/v1\n"))
        assertFalse(ciphertext.decodeToString().contains("Moin"))
    }

    @Test
    fun encryptingToNobodyIsRefused() {
        assertFailsWith<AgeException> { encrypt("Moin".encodeToByteArray(), emptyList()) }
    }

    @Test
    fun garbageIsNeitherAnIdentityNorARecipient() {
        assertFailsWith<AgeException> { identityToRecipient("not-a-key") }
        assertFailsWith<AgeException> { encrypt(byteArrayOf(1), listOf("not-a-key")) }
        assertFalse(isValidRecipient("age1"))
        assertTrue(isValidRecipient(identityToRecipient(generateIdentity())))
    }

    @Test
    fun aRecoveryCodeWrapsAndUnwrapsAnIdentity() {
        val identity = generateIdentity()
        val code = "correct-horse-battery-clippy"

        val blob = encryptWithPassphrase(identity.encodeToByteArray(), code, 10u)
        val restored = decryptWithPassphrase(blob, code, 20u)

        assertContentEquals(identity.encodeToByteArray(), restored)
        assertFailsWith<AgeException> { decryptWithPassphrase(blob, "wrong-code", 20u) }
    }

    @Test
    fun aWorkFactorAboveTheCapIsRefused() {
        val blob = encryptWithPassphrase(byteArrayOf(1), "code", 12u)

        assertFailsWith<AgeException> { decryptWithPassphrase(blob, "code", 10u) }
    }

    @Test
    fun surroundingWhitespaceIsTolerated() {
        val identity = generateIdentity()
        val recipient = identityToRecipient("  $identity\n")

        val ciphertext = encrypt("Moin".encodeToByteArray(), listOf(" $recipient "))

        assertEquals("Moin", decrypt(ciphertext, "\t$identity").decodeToString())
    }

    @Test
    fun aFileRoundTripsWithoutLoadingItIntoMemory() {
        val identity = generateIdentity()
        val recipient = identityToRecipient(identity)
        val payload = ByteArray(3 * 1024 * 1024) { (it * 31 % 251).toByte() }
        val plain = scratch("in.bin").also { it.write(payload) }
        val sealed = scratch("in.age")
        val opened = scratch("out.bin")

        val consumed = encryptFile(plain.toString(), sealed.toString(), listOf(recipient))
        val written = decryptFile(sealed.toString(), opened.toString(), identity)

        assertEquals(payload.size.toULong(), consumed)
        assertEquals(payload.size.toULong(), written)
        assertContentEquals(payload, opened.readAll())
        listOf(plain, sealed, opened).forEach { SystemFileSystem.delete(it, mustExist = false) }
    }

    @Test
    fun aStrangerCannotOpenAFile() {
        val recipient = identityToRecipient(generateIdentity())
        val plain = scratch("stranger.bin").also { it.write("secret".encodeToByteArray()) }
        val sealed = scratch("stranger.age")
        encryptFile(plain.toString(), sealed.toString(), listOf(recipient))

        assertFailsWith<AgeException> {
            decryptFile(sealed.toString(), scratch("stranger-out.bin").toString(), generateIdentity())
        }
        listOf(plain, sealed).forEach { SystemFileSystem.delete(it, mustExist = false) }
    }

    private fun scratch(name: String): Path =
        Path(SystemTemporaryDirectory, "age-kmp-${Random.nextLong().toString(16)}-$name")

    private fun Path.write(bytes: ByteArray) {
        SystemFileSystem.sink(this).buffered().use { it.write(bytes) }
    }

    private fun Path.readAll(): ByteArray =
        SystemFileSystem.source(this).buffered().use { it.readByteArray() }
}
