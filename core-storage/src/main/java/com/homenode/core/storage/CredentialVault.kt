package com.homenode.core.storage

import java.io.Closeable
import java.util.Arrays
import java.util.concurrent.ConcurrentHashMap

@JvmInline
value class VaultKey(val id: String) {
  init {
    require(id.matches(Regex("^[a-zA-Z0-9._-]{3,80}$"))) { "Invalid VaultKey format" }
  }
  override fun toString(): String = "VaultKey($id)"
}

/**
 * Short-lived secret buffer that never exposes raw contents in [toString] and zeros memory on [close] (§4, §8.9).
 */
class SecretBytes(private val raw: ByteArray) : Closeable {
  @Volatile
  private var closed = false

  val size: Int
    get() = raw.size

  inline fun <R> useBytes(block: (ByteArray) -> R): R {
    val snapshot = copyBytes()
    return try {
      block(snapshot)
    } finally {
      Arrays.fill(snapshot, 0.toByte())
      close()
    }
  }

  fun copyBytes(): ByteArray {
    check(!closed) { "SecretBytes already zeroed/closed" }
    return raw.copyOf()
  }

  override fun close() {
    if (!closed) {
      Arrays.fill(raw, 0.toByte())
      closed = true
    }
  }

  override fun toString(): String = "SecretBytes[REDACTED]"
  override fun hashCode(): Int = 0
  override fun equals(other: Any?): Boolean = false
}

/**
 * Keystore-backed credential vault contract (§8.9).
 */
interface CredentialVault {
  suspend fun put(key: VaultKey, secret: SecretBytes): StorageResult<Unit>
  suspend fun get(key: VaultKey): StorageResult<SecretBytes?>
  suspend fun delete(key: VaultKey): StorageResult<Unit>
  suspend fun wipeAll(): StorageResult<Unit>
}

/**
 * In-memory [CredentialVault] for unit tests only.
 */
class InMemoryCredentialVault : CredentialVault {
  private val map = ConcurrentHashMap<String, ByteArray>()

  override suspend fun put(key: VaultKey, secret: SecretBytes): StorageResult<Unit> {
    map[key.id] = secret.copyBytes()
    return StorageResult.Success(Unit)
  }

  override suspend fun get(key: VaultKey): StorageResult<SecretBytes?> {
    val stored = map[key.id] ?: return StorageResult.Success(null)
    return StorageResult.Success(SecretBytes(stored.copyOf()))
  }

  override suspend fun delete(key: VaultKey): StorageResult<Unit> {
    map.remove(key.id)?.let { Arrays.fill(it, 0.toByte()) }
    return StorageResult.Success(Unit)
  }

  override suspend fun wipeAll(): StorageResult<Unit> {
    for (bytes in map.values) {
      Arrays.fill(bytes, 0.toByte())
    }
    map.clear()
    return StorageResult.Success(Unit)
  }
}
