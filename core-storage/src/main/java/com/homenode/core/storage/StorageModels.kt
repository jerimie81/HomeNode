package com.homenode.core.storage

import java.security.SecureRandom

/**
 * Opaque, random, stable identifier for a mount (§8.1). Never derived from user input.
 */
@JvmInline
value class MountId private constructor(val value: String) {
  override fun toString(): String = value

  companion object {
    private val VALID_MOUNT_ID = Regex("^mnt_[a-z0-9]{16}$")
    private val ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
    private val secureRandom = SecureRandom()

    fun generate(): MountId {
      val sb = StringBuilder("mnt_")
      repeat(16) {
        sb.append(ALPHABET[secureRandom.nextInt(ALPHABET.length)])
      }
      return MountId(sb.toString())
    }

    fun parse(raw: String): StorageResult<MountId> {
      return if (VALID_MOUNT_ID.matches(raw)) {
        StorageResult.Success(MountId(raw))
      } else {
        StorageResult.Failure(StorageError.PATH_INVALID, "Malformed MountId")
      }
    }
  }
}

/**
 * Opaque identifier for an allowlisted LAN proxy destination (§10).
 */
@JvmInline
value class DestinationId(val value: String) {
  init {
    require(value.matches(Regex("^[a-zA-Z0-9_-]{3,40}$"))) { "Invalid DestinationId format" }
  }
}

enum class MountKind {
  LOCAL,
  NETWORK,
  CLOUD,
}

enum class StorageProvider(val kind: MountKind) {
  SAF(MountKind.LOCAL),
  SMB(MountKind.NETWORK),
  WEBDAV(MountKind.NETWORK),
  SFTP(MountKind.NETWORK),
  GOOGLE_DRIVE(MountKind.CLOUD),
  ONEDRIVE(MountKind.CLOUD),
  DROPBOX(MountKind.CLOUD),
}

sealed interface MountState {
  data object Connecting : MountState
  data object Ready : MountState
  data class Degraded(val reason: String) : MountState
  data object NeedsReauth : MountState
  data object Unavailable : MountState
  data object Removed : MountState
}

/**
 * Provider-specific configuration containing ZERO secrets (§8.1).
 * Passwords, keys, and OAuth tokens live exclusively in [CredentialVault] referenced by [StorageMount.credentialRef].
 */
sealed interface MountConfig {
  data class SafConfig(
    val treeUriString: String,
    val isRemovableStorage: Boolean = false,
  ) : MountConfig

  data class SmbConfig(
    val hostIpLiteral: String,
    val port: Int = 445,
    val shareName: String,
    val username: String,
    val domain: String = "",
    val requireSigningOrEncryption: Boolean = true,
  ) : MountConfig

  data class WebDavConfig(
    val baseUrl: String,
    val hostIpLiteral: String,
    val port: Int = 443,
    val username: String,
    val allowCleartextLan: Boolean = false,
    val pinnedCertSha256: String? = null,
  ) : MountConfig

  data class SftpConfig(
    val hostIpLiteral: String,
    val port: Int = 22,
    val username: String,
    val remoteBasePath: String = "/",
    val pinnedHostKeyFingerprint: String,
  ) : MountConfig

  data class CloudConfig(
    val provider: StorageProvider,
    val accountDisplayName: String,
    val rootFolderId: String,
    val isAppFolderScopeOnly: Boolean = true,
  ) : MountConfig
}

data class StorageMount(
  val id: MountId,
  val kind: MountKind,
  val provider: StorageProvider,
  val label: String,
  val config: MountConfig,
  val credentialRef: VaultKey?,
  val readOnly: Boolean,
  val state: MountState,
) {
  companion object {
    fun sanitizeLabel(rawLabel: String): String {
      val cleaned = rawLabel
        .filter { !it.isISOControl() }
        .trim()
        .take(48)
      return cleaned.ifEmpty { "Unnamed Mount" }
    }
  }
}

enum class AccessMode {
  READ,
  WRITE,
}

/**
 * Capabilities enforced by `PeerAuthorizer.can(peerId, capability)` (§7).
 */
sealed interface Capability {
  data class Files(val mountId: MountId, val mode: AccessMode) : Capability
  data class Lan(val destinationId: DestinationId) : Capability
}

/**
 * Explicit typed errors required by Knowledge Base §8.3.
 */
enum class StorageError {
  NOT_FOUND,
  EXISTS,
  DENIED,
  PATH_INVALID,
  QUOTA,
  TIMEOUT,
  CANCELLED,
  BUSY,
  UNSUPPORTED,
  PERMISSION_LOST,
  AUTH_REQUIRED,
  RATE_LIMITED,
  UNAVAILABLE,
  DUPLICATE_NAME,
  INTERNAL,
}

class StorageException(
  val error: StorageError,
  override val message: String,
  override val cause: Throwable? = null,
) : Exception(message, cause)

sealed interface StorageResult<out T> {
  data class Success<T>(val value: T) : StorageResult<T>
  data class Failure(val error: StorageError, val message: String) : StorageResult<Nothing>

  val isSuccess: Boolean get() = this is Success
  val isFailure: Boolean get() = this is Failure

  fun getOrNull(): T? = (this as? Success)?.value

  fun getOrThrow(): T = when (this) {
    is Success -> value
    is Failure -> throw StorageException(error, message)
  }
}

inline fun <T> StorageResult<T>.getOrElse(onFailure: (StorageResult.Failure) -> T): T =
  when (this) {
    is StorageResult.Success -> value
    is StorageResult.Failure -> onFailure(this)
  }

enum class WriteMode {
  CREATE_NEW,
  OVERWRITE,
  TRUNCATE,
}

data class FileEntry(
  val name: String,
  val isDirectory: Boolean,
  val sizeBytes: Long,
  val lastModifiedEpochMillis: Long,
)

data class FileStat(
  val name: String,
  val isDirectory: Boolean,
  val sizeBytes: Long,
  val lastModifiedEpochMillis: Long,
  val quotaTotalBytes: Long? = null,
  val quotaAvailableBytes: Long? = null,
)

data class ListPage(
  val entries: List<FileEntry>,
  val nextPageToken: String? = null,
)
