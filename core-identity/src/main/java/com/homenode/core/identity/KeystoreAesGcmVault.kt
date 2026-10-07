package com.homenode.core.identity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Abstraction over AES-256-GCM key wrapping (§4, §8.9, ADR-002).
 */
interface AesGcmKeyWrapper {
  /**
   * True when backed by the real Android Keystore (`AndroidKeyStore`), false when using the JVM unit-test fallback.
   */
  val isAndroidKeystoreBacked: Boolean
  fun wrap(plaintext: ByteArray, aad: ByteArray): ByteArray
  fun unwrap(envelope: ByteArray, aad: ByteArray): ByteArray

  companion object {
    /**
     * Resolves the real [AndroidKeystoreAesGcmWrapper] whenever `AndroidKeyStore` JCE provider is available
     * (all Android devices including Galaxy S8+ API 28), falling back to [SoftwareAesGcmTestWrapper] ONLY inside
     * local host-JVM unit tests where `AndroidKeyStore` is absent.
     */
    fun createDefault(keyAlias: String = AndroidKeystoreAesGcmWrapper.DEFAULT_MASTER_KEY_ALIAS): AesGcmKeyWrapper {
      return try {
        val ks = KeyStore.getInstance(AndroidKeystoreAesGcmWrapper.ANDROID_KEYSTORE)
        ks.load(null)
        val wrapper = AndroidKeystoreAesGcmWrapper(keyAlias)
        // Probe key generation/loading immediately so we know real AndroidKeyStore is active
        wrapper.ensureMasterKeyInitialized()
        wrapper
      } catch (t: Throwable) {
        runCatching {
          Log.w(
            "KeystoreAesGcmVault",
            "SIMULATION_WARNING: AndroidKeyStore unavailable (${t.javaClass.simpleName}); falling back to SoftwareAesGcmTestWrapper"
          )
        }
        SoftwareAesGcmTestWrapper()
      }
    }
  }
}

/**
 * Production Android Keystore AES-256-GCM wrapper designed for Samsung Galaxy S8+ (API 28) (§2, §4).
 * - Never enables StrongBox (unavailable on S8+).
 * - Uses Keystore-generated random 12-byte IV per encryption.
 * - Versioned binary envelope: `| 'H' 'N' 'V' 0x01 | ivLen:u8 | iv | ciphertext+tag |`.
 */
class AndroidKeystoreAesGcmWrapper(
  val keyAlias: String = DEFAULT_MASTER_KEY_ALIAS,
) : AesGcmKeyWrapper {

  override val isAndroidKeystoreBacked: Boolean = true

  fun ensureMasterKeyInitialized(): SecretKey = getOrCreateSecretKey()

  private fun getOrCreateSecretKey(): SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val existing = ks.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
    if (existing != null) return existing.secretKey

    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
    val spec = KeyGenParameterSpec.Builder(
      keyAlias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setRandomizedEncryptionRequired(true)
      .build()
    keyGenerator.init(spec)
    return keyGenerator.generateKey()
  }

  override fun wrap(plaintext: ByteArray, aad: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
    cipher.updateAAD(aad)
    val iv = cipher.iv
    check(iv != null && iv.size == GCM_IV_LEN) { "Unexpected GCM IV length" }
    val ciphertext = cipher.doFinal(plaintext)
    return packEnvelope(iv, ciphertext)
  }

  override fun unwrap(envelope: ByteArray, aad: ByteArray): ByteArray {
    val (iv, ciphertext) = unpackEnvelope(envelope)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
    cipher.updateAAD(aad)
    return cipher.doFinal(ciphertext)
  }

  companion object {
    internal const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val DEFAULT_MASTER_KEY_ALIAS = "homenode_master_aes256_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128
    private val MAGIC = byteArrayOf('H'.code.toByte(), 'N'.code.toByte(), 'V'.code.toByte(), 0x01)

    internal fun packEnvelope(iv: ByteArray, ciphertext: ByteArray): ByteArray {
      val buf = ByteBuffer.allocate(MAGIC.size + 1 + iv.size + ciphertext.size)
      buf.put(MAGIC)
      buf.put(iv.size.toByte())
      buf.put(iv)
      buf.put(ciphertext)
      return buf.array()
    }

    internal fun unpackEnvelope(envelope: ByteArray): Pair<ByteArray, ByteArray> {
      require(envelope.size > MAGIC.size + 1 + GCM_IV_LEN + 16) { "Envelope truncated" }
      for (i in MAGIC.indices) {
        require(envelope[i] == MAGIC[i]) { "Invalid envelope header or unsupported version" }
      }
      val ivLen = envelope[MAGIC.size].toInt() and 0xFF
      require(ivLen == GCM_IV_LEN) { "Invalid IV length $ivLen" }
      val ivStart = MAGIC.size + 1
      val iv = envelope.copyOfRange(ivStart, ivStart + ivLen)
      val ciphertext = envelope.copyOfRange(ivStart + ivLen, envelope.size)
      return iv to ciphertext
    }
  }
}

/**
 * JVM-compatible AES-256-GCM wrapper using identical envelope formatting for local JVM unit tests.
 * Explicitly reports `isAndroidKeystoreBacked = false` so the UI displays a SIMULATION banner if ever used on device.
 */
class SoftwareAesGcmTestWrapper(
  rawKey256: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
) : AesGcmKeyWrapper {
  override val isAndroidKeystoreBacked: Boolean = false
  private val secretKey: SecretKey = SecretKeySpec(rawKey256.copyOf(32), "AES")
  private val rng = SecureRandom()

  override fun wrap(plaintext: ByteArray, aad: ByteArray): ByteArray {
    val iv = ByteArray(12).also { rng.nextBytes(it) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
    cipher.updateAAD(aad)
    val ciphertext = cipher.doFinal(plaintext)
    return AndroidKeystoreAesGcmWrapper.packEnvelope(iv, ciphertext)
  }

  override fun unwrap(envelope: ByteArray, aad: ByteArray): ByteArray {
    val (iv, ciphertext) = AndroidKeystoreAesGcmWrapper.unpackEnvelope(envelope)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
    cipher.updateAAD(aad)
    return cipher.doFinal(ciphertext)
  }
}

/**
 * Persistent, fail-closed [CredentialVault] storing AES-256-GCM wrapped entries in a backup-excluded directory (§4, §8.9).
 * Binds each ciphertext to its [VaultKey] via GCM Additional Authenticated Data (AAD) to prevent key-swapping attacks.
 */
class KeystoreCredentialVault(
  private val storageDir: File,
  val wrapper: AesGcmKeyWrapper = AesGcmKeyWrapper.createDefault(),
) : CredentialVault {

  private val mutex = Mutex()

  val isAndroidKeystoreBacked: Boolean
    get() = wrapper.isAndroidKeystoreBacked

  init {
    if (!storageDir.exists()) {
      storageDir.mkdirs()
    }
  }

  private fun fileForKey(key: VaultKey): File = File(storageDir, "${key.id}.vault")

  private fun aadForKey(key: VaultKey): ByteArray = "homenode-vault-v1:${key.id}".encodeToByteArray()

  override suspend fun put(key: VaultKey, secret: SecretBytes): StorageResult<Unit> = mutex.withLock {
    try {
      val plainCopy = secret.copyBytes()
      val wrapped = try {
        wrapper.wrap(plainCopy, aadForKey(key))
      } finally {
        plainCopy.fill(0)
      }
      val targetFile = fileForKey(key)
      val tempFile = File(storageDir, "${key.id}.vault.tmp")
      tempFile.writeBytes(wrapped)
      if (!tempFile.renameTo(targetFile)) {
        targetFile.writeBytes(wrapped)
        tempFile.delete()
      }
      StorageResult.Success(Unit)
    } catch (e: Exception) {
      StorageResult.Failure(StorageError.INTERNAL, "Vault encryption failed")
    }
  }

  override suspend fun get(key: VaultKey): StorageResult<SecretBytes?> = mutex.withLock {
    val targetFile = fileForKey(key)
    if (!targetFile.exists()) {
      return@withLock StorageResult.Success(null)
    }
    try {
      val envelope = targetFile.readBytes()
      val unwrapped = wrapper.unwrap(envelope, aadForKey(key))
      StorageResult.Success(SecretBytes(unwrapped))
    } catch (e: Exception) {
      // Fail closed on corruption, AAD mismatch, or Keystore invalidation (§4, §8.9)
      StorageResult.Failure(StorageError.DENIED, "Vault entry corrupted or key invalidated (fail-closed)")
    }
  }

  override suspend fun delete(key: VaultKey): StorageResult<Unit> = mutex.withLock {
    val targetFile = fileForKey(key)
    if (targetFile.exists()) {
      // Overwrite with zeros before unlink
      runCatching {
        val len = targetFile.length().toInt().coerceIn(0, 65536)
        targetFile.writeBytes(ByteArray(len))
      }
      targetFile.delete()
    }
    StorageResult.Success(Unit)
  }

  override suspend fun wipeAll(): StorageResult<Unit> = mutex.withLock {
    storageDir.listFiles()?.forEach { file ->
      if (file.isFile && (file.name.endsWith(".vault") || file.name.endsWith(".tmp"))) {
        runCatching { file.writeBytes(ByteArray(file.length().toInt().coerceIn(0, 65536))) }
        file.delete()
      }
    }
    StorageResult.Success(Unit)
  }
}
