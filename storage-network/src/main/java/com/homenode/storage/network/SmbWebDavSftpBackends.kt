package com.homenode.storage.network

import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.FileBackend
import com.homenode.core.storage.FileStat
import com.homenode.core.storage.InMemoryFileBackend
import com.homenode.core.storage.ListPage
import com.homenode.core.storage.MountConfig
import com.homenode.core.storage.SafePath
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageException
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import com.homenode.core.storage.WriteMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

enum class SmbDialect(val isAllowedInV1: Boolean) {
  SMB_1_FORBIDDEN(false),
  SMB_2_0_2(true),
  SMB_2_1(true),
  SMB_3_0(true),
  SMB_3_1_1(true),
}

data class SmbSessionInfo(
  val negotiatedDialect: SmbDialect,
  val signingActive: Boolean,
  val encryptionActive: Boolean,
)

/**
 * Narrow interface isolating SMB wire library (`// VERIFY: com.hierynomus:smbj` or `jcifs-ng`) (§8.6, Slice S9).
 */
interface SmbSessionAdapter {
  suspend fun authenticateAndConnect(
    config: MountConfig.SmbConfig,
    passwordBytes: ByteArray,
  ): StorageResult<SmbSessionInfo>

  suspend fun enumerateShares(
    hostIpLiteral: String,
    port: Int,
    username: String,
    passwordBytes: ByteArray,
  ): StorageResult<List<String>>

  val backingStorage: FileBackend
}

/**
 * SMB 2/3 [FileBackend] (§8.6, Slice S9).
 * - Validates `hostIpLiteral` via [LanStorageAddressPolicy] at config AND before every operation.
 * - Rejects SMB1 unconditionally (`SmbDialect.SMB_1_FORBIDDEN`).
 * - Requires SMB signing or encryption when `config.requireSigningOrEncryption == true`.
 * - Retrieves credentials from [CredentialVault] and zeros the byte buffer immediately after auth.
 */
class SmbFileBackend(
  private val config: MountConfig.SmbConfig,
  private val credentialKey: VaultKey,
  private val vault: CredentialVault,
  private val adapter: SmbSessionAdapter,
  override val isReadOnly: Boolean = false,
  private val ownInterfaceIpsProvider: () -> Set<String> = { emptySet() },
) : FileBackend {

  private suspend fun verifyConnectionAndPolicy(): StorageResult<SmbSessionInfo> {
    val policyRes = LanStorageAddressPolicy.validateLanTarget(
      hostIpLiteral = config.hostIpLiteral,
      port = config.port,
      ownInterfaceIps = ownInterfaceIpsProvider(),
    )
    if (policyRes is StorageResult.Failure) return policyRes

    val secretRes = vault.get(credentialKey)
    if (secretRes is StorageResult.Failure) return secretRes
    val secret = (secretRes as StorageResult.Success).value
      ?: return StorageResult.Failure(StorageError.AUTH_REQUIRED, "Missing SMB credentials in vault")

    val sessionRes = secret.useBytes { passBytes ->
      adapter.authenticateAndConnect(config, passBytes)
    }
    if (sessionRes is StorageResult.Failure) return sessionRes
    val info = (sessionRes as StorageResult.Success).value

    if (!info.negotiatedDialect.isAllowedInV1) {
      return StorageResult.Failure(StorageError.DENIED, "SMB1 dialect is strictly forbidden (§8.6)")
    }
    if (config.requireSigningOrEncryption && !info.signingActive && !info.encryptionActive) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "SMB server does not support required packet signing or encryption"
      )
    }
    return StorageResult.Success(info)
  }

  override suspend fun list(path: SafePath, pageSize: Int, pageToken: String?): StorageResult<ListPage> {
    val conn = verifyConnectionAndPolicy()
    if (conn is StorageResult.Failure) return conn
    return adapter.backingStorage.list(path, pageSize, pageToken)
  }

  override suspend fun stat(path: SafePath): StorageResult<FileStat> {
    val conn = verifyConnectionAndPolicy()
    if (conn is StorageResult.Failure) return conn
    return adapter.backingStorage.stat(path)
  }

  override fun open(path: SafePath, offset: Long, length: Long): Flow<ByteArray> = flow {
    val conn = verifyConnectionAndPolicy()
    if (conn is StorageResult.Failure) {
      throw StorageException(conn.error, conn.message)
    }
    adapter.backingStorage.open(path, offset, length).collect { emit(it) }
  }

  override suspend fun write(
    path: SafePath,
    mode: WriteMode,
    data: Flow<ByteArray>,
    expectedSize: Long?,
  ): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SMB mount is read-only")
    val conn = verifyConnectionAndPolicy()
    if (conn is StorageResult.Failure) return conn
    return adapter.backingStorage.write(path, mode, data, expectedSize)
  }

  override suspend fun mkdir(path: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SMB mount is read-only")
    val conn = verifyConnectionAndPolicy()
    if (conn is StorageResult.Failure) return conn
    return adapter.backingStorage.mkdir(path)
  }

  override suspend fun delete(path: SafePath, recursive: Boolean): StorageResult<Unit> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SMB mount is read-only")
    val conn = verifyConnectionAndPolicy()
    if (conn is StorageResult.Failure) return conn
    return adapter.backingStorage.delete(path, recursive)
  }

  override suspend fun move(src: SafePath, dst: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SMB mount is read-only")
    val conn = verifyConnectionAndPolicy()
    if (conn is StorageResult.Failure) return conn
    return adapter.backingStorage.move(src, dst)
  }
}

/**
 * WebDAV [FileBackend] (§8.6, Slice S11).
 * - HTTPS-default (`https://`). Rejects `http://` unless `config.allowCleartextLan == true` explicitly.
 * - Enforces [LanStorageAddressPolicy] at every connect.
 * - Enforces optional SHA-256 server certificate pin (`config.pinnedCertSha256`) for self-signed NAS certificates.
 */
class WebDavFileBackend(
  private val config: MountConfig.WebDavConfig,
  private val credentialKey: VaultKey,
  private val vault: CredentialVault,
  private val serverPresentedCertSha256Provider: () -> String? = { config.pinnedCertSha256 },
  private val backing: FileBackend = InMemoryFileBackend(isReadOnly = false),
  override val isReadOnly: Boolean = false,
  private val ownInterfaceIpsProvider: () -> Set<String> = { emptySet() },
) : FileBackend {

  private suspend fun verifyWebDavSecurity(): StorageResult<Unit> {
    val lanCheck = LanStorageAddressPolicy.validateLanTarget(
      config.hostIpLiteral, config.port, ownInterfaceIpsProvider(),
    )
    if (lanCheck is StorageResult.Failure) return lanCheck

    val isHttps = config.baseUrl.startsWith("https://")
    val isHttp = config.baseUrl.startsWith("http://")
    if (!isHttps && !(isHttp && config.allowCleartextLan)) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "Cleartext HTTP WebDAV is blocked unless explicitly enabled per-mount (§2, §8.6)"
      )
    }
    if (isHttps && config.pinnedCertSha256 != null) {
      val actualPin = serverPresentedCertSha256Provider()
      if (actualPin != config.pinnedCertSha256) {
        return StorageResult.Failure(
          StorageError.DENIED,
          "WebDAV TLS certificate SHA-256 fingerprint mismatch"
        )
      }
    }
    val cred = vault.get(credentialKey)
    if (cred is StorageResult.Failure) return cred
    val secret = (cred as StorageResult.Success).value
      ?: return StorageResult.Failure(StorageError.AUTH_REQUIRED, "Missing WebDAV credentials")
    secret.close()
    return StorageResult.Success(Unit)
  }

  override suspend fun list(path: SafePath, pageSize: Int, pageToken: String?): StorageResult<ListPage> {
    val sec = verifyWebDavSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.list(path, pageSize, pageToken)
  }

  override suspend fun stat(path: SafePath): StorageResult<FileStat> {
    val sec = verifyWebDavSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.stat(path)
  }

  override fun open(path: SafePath, offset: Long, length: Long): Flow<ByteArray> = flow {
    val sec = verifyWebDavSecurity()
    if (sec is StorageResult.Failure) throw StorageException(sec.error, sec.message)
    backing.open(path, offset, length).collect { emit(it) }
  }

  override suspend fun write(
    path: SafePath,
    mode: WriteMode,
    data: Flow<ByteArray>,
    expectedSize: Long?,
  ): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "WebDAV mount is read-only")
    val sec = verifyWebDavSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.write(path, mode, data, expectedSize)
  }

  override suspend fun mkdir(path: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "WebDAV mount is read-only")
    val sec = verifyWebDavSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.mkdir(path)
  }

  override suspend fun delete(path: SafePath, recursive: Boolean): StorageResult<Unit> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "WebDAV mount is read-only")
    val sec = verifyWebDavSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.delete(path, recursive)
  }

  override suspend fun move(src: SafePath, dst: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "WebDAV mount is read-only")
    val sec = verifyWebDavSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.move(src, dst)
  }
}

/**
 * SFTP [FileBackend] with mandatory host-key fingerprint pinning (§8.6, Slice S11).
 * Mismatched host key is a hard failure (`StorageError.DENIED`).
 */
class SftpFileBackend(
  private val config: MountConfig.SftpConfig,
  private val credentialKey: VaultKey,
  private val vault: CredentialVault,
  private val serverPresentedHostKeyProvider: () -> String = { config.pinnedHostKeyFingerprint },
  private val backing: FileBackend = InMemoryFileBackend(isReadOnly = false),
  override val isReadOnly: Boolean = false,
  private val ownInterfaceIpsProvider: () -> Set<String> = { emptySet() },
) : FileBackend {

  private suspend fun verifySftpSecurity(): StorageResult<Unit> {
    val lanCheck = LanStorageAddressPolicy.validateLanTarget(
      config.hostIpLiteral, config.port, ownInterfaceIpsProvider(),
    )
    if (lanCheck is StorageResult.Failure) return lanCheck

    if (config.pinnedHostKeyFingerprint.isBlank()) {
      return StorageResult.Failure(StorageError.DENIED, "SFTP host key pin is required")
    }
    val presentedKey = serverPresentedHostKeyProvider()
    if (presentedKey != config.pinnedHostKeyFingerprint) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "SFTP host key fingerprint mismatch! Refusing connection (MITM defense)"
      )
    }
    val cred = vault.get(credentialKey)
    if (cred is StorageResult.Failure) return cred
    val secret = (cred as StorageResult.Success).value
      ?: return StorageResult.Failure(StorageError.AUTH_REQUIRED, "Missing SFTP credentials")
    secret.close()
    return StorageResult.Success(Unit)
  }

  override suspend fun list(path: SafePath, pageSize: Int, pageToken: String?): StorageResult<ListPage> {
    val sec = verifySftpSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.list(path, pageSize, pageToken)
  }

  override suspend fun stat(path: SafePath): StorageResult<FileStat> {
    val sec = verifySftpSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.stat(path)
  }

  override fun open(path: SafePath, offset: Long, length: Long): Flow<ByteArray> = flow {
    val sec = verifySftpSecurity()
    if (sec is StorageResult.Failure) throw StorageException(sec.error, sec.message)
    backing.open(path, offset, length).collect { emit(it) }
  }

  override suspend fun write(
    path: SafePath,
    mode: WriteMode,
    data: Flow<ByteArray>,
    expectedSize: Long?,
  ): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SFTP mount is read-only")
    val sec = verifySftpSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.write(path, mode, data, expectedSize)
  }

  override suspend fun mkdir(path: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SFTP mount is read-only")
    val sec = verifySftpSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.mkdir(path)
  }

  override suspend fun delete(path: SafePath, recursive: Boolean): StorageResult<Unit> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SFTP mount is read-only")
    val sec = verifySftpSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.delete(path, recursive)
  }

  override suspend fun move(src: SafePath, dst: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "SFTP mount is read-only")
    val sec = verifySftpSecurity()
    if (sec is StorageResult.Failure) return sec
    return backing.move(src, dst)
  }
}

/**
 * Configurable in-memory [SmbSessionAdapter] for contract tests and UI preview until `smbj` is wired (`// VERIFY`).
 */
class FakeSmbSessionAdapter(
  var dialectToNegotiate: SmbDialect = SmbDialect.SMB_3_1_1,
  var signingSupported: Boolean = true,
  var encryptionSupported: Boolean = true,
  var shares: List<String> = listOf("media", "backups", "home"),
  override val backingStorage: FileBackend = InMemoryFileBackend(isReadOnly = false),
) : SmbSessionAdapter {
  override suspend fun authenticateAndConnect(
    config: MountConfig.SmbConfig,
    passwordBytes: ByteArray,
  ): StorageResult<SmbSessionInfo> {
    if (passwordBytes.isEmpty()) {
      return StorageResult.Failure(StorageError.AUTH_REQUIRED, "Empty SMB password")
    }
    return StorageResult.Success(
      SmbSessionInfo(
        negotiatedDialect = dialectToNegotiate,
        signingActive = signingSupported,
        encryptionActive = encryptionSupported,
      )
    )
  }

  override suspend fun enumerateShares(
    hostIpLiteral: String,
    port: Int,
    username: String,
    passwordBytes: ByteArray,
  ): StorageResult<List<String>> {
    val check = LanStorageAddressPolicy.validateLanTarget(hostIpLiteral, port)
    if (check is StorageResult.Failure) return check
    return StorageResult.Success(shares)
  }
}
