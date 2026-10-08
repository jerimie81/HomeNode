package com.homenode.core.identity

import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.bouncycastle.math.ec.rfc7748.X25519

/**
 * Validated 32-byte X25519 public key identifier used across `:core-identity` (§4).
 */
@JvmInline
value class PeerId private constructor(val base64Url: String) {
  val shortId: String get() = base64Url.take(8)

  fun toBytes(): ByteArray = Base64.getUrlDecoder().decode(base64Url)

  override fun toString(): String = "PeerId($shortId…)"

  companion object {
    fun fromBytes(bytes: ByteArray): PeerId {
      require(bytes.size == 32 && !bytes.all { it == 0.toByte() }) {
        "X25519 public key must be 32 non-zero bytes"
      }
      return PeerId(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes))
    }

    fun parse(encoded: String): PeerId? {
      return try {
        val decoded = Base64.getUrlDecoder().decode(encoded)
        if (decoded.size == 32 && !decoded.all { it == 0.toByte() }) {
          val canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)
          if (canonical == encoded) PeerId(canonical) else null
        } else {
          null
        }
      } catch (e: Exception) {
        null
      }
    }
  }
}

class IdentityUnavailableException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class NodePublicIdentity(
  val nodeId: String,
  val publicKey: PeerId,
)

/**
 * Manages the node's static Curve25519 (X25519) keypair on API 28 (§4, Slice S3).
 * - Uses vetted RFC 7748 X25519 implementation (`org.bouncycastle.math.ec.rfc7748.X25519`) for basepoint
 *   public key derivation and Diffie-Hellman shared secret calculation (WireGuard compatible).
 * - Wraps 32-byte private key inside [CredentialVault].
 * - **Fail-closed:** if marker file indicates an identity was provisioned, but the vault entry is missing or corrupted,
 *   returns `StorageResult.Failure(StorageError.DENIED)` and NEVER silently regenerates.
 */
class NodeIdentityManager(
  private val stateDir: File,
  private val vault: CredentialVault,
) {
  private val mutex = Mutex()
  private val markerFile = File(stateDir, "identity_meta_v1.prop")
  private val secureRandom = SecureRandom()

  init {
    if (!stateDir.exists()) stateDir.mkdirs()
  }

  suspend fun loadOrInitializeIdentity(): StorageResult<NodePublicIdentity> = mutex.withLock {
    val hasProvisionedMarker = markerFile.exists()
    val vaultResult = vault.get(PRIVATE_KEY_VAULT_KEY)

    if (vaultResult is StorageResult.Failure) {
      return@withLock StorageResult.Failure(
        StorageError.DENIED,
        "IdentityUnavailable: Keystore or vault corrupted (fail-closed; refusing silent regeneration)"
      )
    }

    val existingSecret = (vaultResult as StorageResult.Success).value
    if (hasProvisionedMarker && existingSecret == null) {
      return@withLock StorageResult.Failure(
        StorageError.DENIED,
        "IdentityUnavailable: Private key missing despite provisioned marker (fail-closed)"
      )
    }

    if (existingSecret != null) {
      return@withLock existingSecret.useBytes { privBytes ->
        if (privBytes.size != 32) {
          StorageResult.Failure(StorageError.DENIED, "IdentityUnavailable: Invalid private key length")
        } else {
          val pubBytes = derivePublicKeyBytes(privBytes)
          val peerId = PeerId.fromBytes(pubBytes)
          val derivedNodeId = deriveNodeId(pubBytes)
          if (hasProvisionedMarker) {
            val markerText = runCatching { markerFile.readText() }.getOrDefault("")
            val expectedLine = "publicKey=${peerId.base64Url}"
            if (!markerText.contains(expectedLine)) {
              return@useBytes StorageResult.Failure(
                StorageError.DENIED,
                "IdentityUnavailable: Marker public key mismatch with vault private key (fail-closed)"
              )
            }
          } else {
            // Re-persist metadata marker if missing while valid vault key is intact
            runCatching {
              markerFile.writeText("version=1\nnodeId=$derivedNodeId\npublicKey=${peerId.base64Url}\n")
            }
          }
          StorageResult.Success(NodePublicIdentity(nodeId = derivedNodeId, publicKey = peerId))
        }
      }
    }

    // First-run provisioning
    return@withLock generateAndPersistNewIdentityLocked()
  }


  /**
   * Explicit, warned user action to regenerate node identity when Keystore is invalidated (§4).
   */
  suspend fun explicitUserRegenerateIdentity(): StorageResult<NodePublicIdentity> = mutex.withLock {
    vault.delete(PRIVATE_KEY_VAULT_KEY)
    if (markerFile.exists()) markerFile.delete()
    generateAndPersistNewIdentityLocked()
  }

  private suspend fun generateAndPersistNewIdentityLocked(): StorageResult<NodePublicIdentity> {
    val privBytes = ByteArray(32)
    X25519.generatePrivateKey(secureRandom, privBytes)

    val pubBytes = derivePublicKeyBytes(privBytes)
    val peerId = PeerId.fromBytes(pubBytes)
    val nodeId = deriveNodeId(pubBytes)

    val putRes = vault.put(PRIVATE_KEY_VAULT_KEY, SecretBytes(privBytes.copyOf()))
    privBytes.fill(0)
    if (putRes is StorageResult.Failure) {
      return putRes
    }
    markerFile.writeText("version=1\nnodeId=$nodeId\npublicKey=${peerId.base64Url}\n")
    return StorageResult.Success(NodePublicIdentity(nodeId = nodeId, publicKey = peerId))
  }

  companion object {
    val PRIVATE_KEY_VAULT_KEY = VaultKey("node.identity.x25519.priv")

    /**
     * Generates a fresh RFC 7748 X25519 keypair `(privateKey32, publicKeyPeerId)` using [SecureRandom].
     */
    fun generateEphemeralKeypair(rng: SecureRandom = SecureRandom()): Pair<SecretBytes, PeerId> {
      val priv = ByteArray(32)
      X25519.generatePrivateKey(rng, priv)
      val pub = derivePublicKeyBytes(priv)
      val secret = SecretBytes(priv.copyOf())
      priv.fill(0)
      return secret to PeerId.fromBytes(pub)
    }

    /**
     * Derives the 32-byte RFC 7748 X25519 public key (`u = 9` basepoint scalar multiplication).
     * Compatible with WireGuard static/ephemeral Curve25519 keys.
     */
    fun derivePublicKeyBytes(privateKey32: ByteArray): ByteArray {
      require(privateKey32.size == 32) { "X25519 private key must be 32 bytes" }
      val pub = ByteArray(32)
      X25519.scalarMultBase(privateKey32, 0, pub, 0)
      return pub
    }

    /**
     * Computes the 32-byte RFC 7748 X25519 Diffie-Hellman shared secret and rejects all-zero low-order points.
     */
    fun computeSharedSecret(privateKey32: ByteArray, peerPublicKey32: ByteArray): StorageResult<SecretBytes> {
      if (privateKey32.size != 32 || peerPublicKey32.size != 32) {
        return StorageResult.Failure(StorageError.PATH_INVALID, "X25519 keys must be 32 bytes")
      }
      val out = ByteArray(32)
      X25519.scalarMult(privateKey32, 0, peerPublicKey32, 0, out, 0)
      // RFC 7748 §6.1 constant-time all-zero check (rejects small-subgroup / low-order public keys)
      var acc = 0
      for (b in out) {
        acc = acc or (b.toInt() and 0xFF)
      }
      if (acc == 0) {
        out.fill(0)
        return StorageResult.Failure(StorageError.DENIED, "Rejected low-order X25519 public key (all-zero DH output)")
      }
      val secret = SecretBytes(out.copyOf())
      out.fill(0)
      return StorageResult.Success(secret)
    }

    internal fun deriveNodeId(publicKey32: ByteArray): String {
      val hash = MessageDigest.getInstance("SHA-256").digest(publicKey32)
      return "hn_" + Base64.getUrlEncoder().withoutPadding().encodeToString(hash.copyOfRange(0, 9)).lowercase()
    }
  }
}
