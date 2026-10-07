package com.homenode.storage.cloud

import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.FileBackend
import com.homenode.core.storage.FileEntry
import com.homenode.core.storage.FileStat
import com.homenode.core.storage.ListPage
import com.homenode.core.storage.SafePath
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageException
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import com.homenode.core.storage.WriteMode
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HttpsURLConnection
import kotlin.math.min
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Least-privilege default OAuth 2.0 scopes per cloud provider (§8.8, ADR-009).
 */
object CloudProviderScopes {
  const val REDIRECT_URI = "com.homenode.oauth:/oauth2redirect"

  fun defaultScopes(provider: StorageProvider, fullAccessOptIn: Boolean = false): List<String> =
    when (provider) {
      StorageProvider.GOOGLE_DRIVE -> if (fullAccessOptIn) {
        listOf("https://www.googleapis.com/auth/drive.readonly")
      } else {
        listOf("https://www.googleapis.com/auth/drive.file")
      }
      StorageProvider.ONEDRIVE -> if (fullAccessOptIn) {
        listOf("Files.Read.All", "offline_access")
      } else {
        listOf("Files.ReadWrite.AppFolder", "offline_access")
      }
      StorageProvider.DROPBOX -> listOf(
        "files.metadata.read",
        "files.content.read",
        "files.content.write",
      )
      else -> emptyList()
    }
}

data class PkceAuthRequest(
  val provider: StorageProvider,
  val publicClientId: String,
  val redirectUri: String,
  val state: String,
  val codeVerifier: SecretBytes,
  val codeChallengeS256: String,
  val scopes: List<String>,
  val systemBrowserAuthorizationUrl: String,
) {
  override fun toString(): String =
    "PkceAuthRequest(provider=$provider, state=$state, scopes=$scopes, codeVerifier=REDACTED)"
}

enum class TokenRefreshOutcome {
  SUCCESS,
  INVALID_GRANT_REVOKED,
  RATE_LIMITED,
  NETWORK_UNAVAILABLE,
}

data class TokenExchangeResponse(
  val outcome: TokenRefreshOutcome,
  val accessTokenBytes: ByteArray? = null,
  val refreshTokenBytes: ByteArray? = null,
  val expiresInSeconds: Long = 3600L,
)

interface OAuthTokenEndpointAdapter {
  val isSimulatedEndpoint: Boolean
    get() = false

  suspend fun exchangeCodeWithPkce(
    provider: StorageProvider,
    publicClientId: String,
    redirectUri: String,
    authorizationCode: String,
    codeVerifierBytes: ByteArray,
  ): TokenExchangeResponse

  suspend fun refreshAccessToken(
    provider: StorageProvider,
    publicClientId: String,
    refreshTokenBytes: ByteArray,
  ): TokenExchangeResponse

  suspend fun revokeTokenAtProvider(
    provider: StorageProvider,
    tokenBytes: ByteArray,
  ): Boolean
}

/**
 * Production HTTPS OAuth 2.0 + PKCE token endpoint client using [HttpsURLConnection] (§8.8, Slice S12).
 * - Enforces TLS-only (`HttpsURLConnection`), 10s connect timeout, 15s read timeout, and 64 KiB response cap.
 * - Never sends or embeds a `client_secret` (public native client with PKCE only).
 * - Never logs request bodies, authorization codes, or token responses.
 */
class HttpsOAuthTokenEndpointAdapter(
  private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(4),
) : OAuthTokenEndpointAdapter {

  override val isSimulatedEndpoint: Boolean = false

  private fun tokenEndpointUrl(provider: StorageProvider): String = when (provider) {
    StorageProvider.GOOGLE_DRIVE -> "https://oauth2.googleapis.com/token"
    StorageProvider.ONEDRIVE -> "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    StorageProvider.DROPBOX -> "https://api.dropboxapi.com/oauth2/token"
    else -> throw IllegalArgumentException("Unsupported OAuth provider: $provider")
  }

  override suspend fun exchangeCodeWithPkce(
    provider: StorageProvider,
    publicClientId: String,
    redirectUri: String,
    authorizationCode: String,
    codeVerifierBytes: ByteArray,
  ): TokenExchangeResponse = withContext(ioDispatcher) {
    val verifierStr = String(codeVerifierBytes, Charsets.UTF_8)
    val params = mapOf(
      "grant_type" to "authorization_code",
      "client_id" to publicClientId,
      "redirect_uri" to redirectUri,
      "code" to authorizationCode,
      "code_verifier" to verifierStr,
    )
    executeTokenPost(tokenEndpointUrl(provider), params)
  }

  override suspend fun refreshAccessToken(
    provider: StorageProvider,
    publicClientId: String,
    refreshTokenBytes: ByteArray,
  ): TokenExchangeResponse = withContext(ioDispatcher) {
    val refreshTokenStr = String(refreshTokenBytes, Charsets.UTF_8)
    val params = mapOf(
      "grant_type" to "refresh_token",
      "client_id" to publicClientId,
      "refresh_token" to refreshTokenStr,
    )
    executeTokenPost(tokenEndpointUrl(provider), params)
  }

  override suspend fun revokeTokenAtProvider(
    provider: StorageProvider,
    tokenBytes: ByteArray,
  ): Boolean = withContext(ioDispatcher) {
    val tokenStr = String(tokenBytes, Charsets.UTF_8)
    try {
      when (provider) {
        StorageProvider.GOOGLE_DRIVE -> {
          val conn = (URL("https://oauth2.googleapis.com/revoke").openConnection() as HttpsURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            doOutput = true
            setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
          }
          try {
            val body = "token=${URLEncoder.encode(tokenStr, "UTF-8")}".encodeToByteArray()
            conn.outputStream.use { it.write(body) }
            conn.responseCode in 200..299
          } finally {
            conn.disconnect()
          }
        }
        StorageProvider.DROPBOX -> {
          val conn = (URL("https://api.dropboxapi.com/2/auth/token/revoke").openConnection() as HttpsURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            setRequestProperty("Authorization", "Bearer $tokenStr")
          }
          try {
            conn.responseCode in 200..299
          } finally {
            conn.disconnect()
          }
        }
        else -> true
      }
    } catch (e: Exception) {
      false
    }
  }

  private fun executeTokenPost(urlStr: String, formParams: Map<String, String>): TokenExchangeResponse {
    var conn: HttpsURLConnection? = null
    return try {
      val url = URL(urlStr)
      check(url.protocol.equals("https", ignoreCase = true)) { "OAuth token endpoint must use HTTPS" }
      conn = (url.openConnection() as HttpsURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = CONNECT_TIMEOUT_MS
        readTimeout = READ_TIMEOUT_MS
        instanceFollowRedirects = false
        doOutput = true
        setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        setRequestProperty("Accept", "application/json")
      }
      val encodedForm = formParams.entries.joinToString("&") { (k, v) ->
        "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
      }.encodeToByteArray()
      conn.outputStream.use { out ->
        out.write(encodedForm)
        out.flush()
      }
      encodedForm.fill(0)

      val status = conn.responseCode
      val stream: InputStream? = if (status in 200..299) conn.inputStream else conn.errorStream
      val bodyBytes = stream?.use { readBoundedBytes(it, MAX_TOKEN_RESPONSE_BYTES) } ?: ByteArray(0)
      val bodyText = String(bodyBytes, Charsets.UTF_8)
      bodyBytes.fill(0)

      when {
        status in 200..299 -> {
          val json = JSONObject(bodyText)
          val accessToken = json.optString("access_token", "")
          val refreshToken = json.optString("refresh_token", "")
          val expiresIn = json.optLong("expires_in", 3600L).coerceAtLeast(60L)
          if (accessToken.isBlank()) {
            TokenExchangeResponse(TokenRefreshOutcome.INVALID_GRANT_REVOKED)
          } else {
            TokenExchangeResponse(
              outcome = TokenRefreshOutcome.SUCCESS,
              accessTokenBytes = accessToken.encodeToByteArray(),
              refreshTokenBytes = if (refreshToken.isNotBlank()) refreshToken.encodeToByteArray() else null,
              expiresInSeconds = expiresIn,
            )
          }
        }
        status == HttpURLConnection.HTTP_BAD_REQUEST || status == HttpURLConnection.HTTP_UNAUTHORIZED -> {
          TokenExchangeResponse(TokenRefreshOutcome.INVALID_GRANT_REVOKED)
        }
        status == 429 -> {
          TokenExchangeResponse(TokenRefreshOutcome.RATE_LIMITED)
        }
        else -> {
          TokenExchangeResponse(TokenRefreshOutcome.NETWORK_UNAVAILABLE)
        }
      }
    } catch (e: Exception) {
      TokenExchangeResponse(TokenRefreshOutcome.NETWORK_UNAVAILABLE)
    } finally {
      conn?.disconnect()
    }
  }

  private fun readBoundedBytes(input: InputStream, maxBytes: Int): ByteArray {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(4096)
    var total = 0
    while (true) {
      val n = input.read(buf)
      if (n <= 0) break
      total += n
      if (total > maxBytes) {
        throw IllegalStateException("OAuth response exceeded $maxBytes bytes cap")
      }
      out.write(buf, 0, n)
    }
    return out.toByteArray()
  }

  companion object {
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
  }
}

/**
 * Provider-agnostic OAuth 2.0 + PKCE coordinator (§8.8, Slice S12).
 * Enforces:
 * - RFC 7636 `S256` PKCE challenge + 128-bit `state` + exact `redirectUri` verification.
 * - System browser / Custom Tabs URL generation (never embedded WebView; never client secret).
 * - Single-flight token refresh per account [VaultKey] via per-account [Mutex].
 * - `invalid_grant` / revoked token maps to `StorageError.AUTH_REQUIRED` (`MountState.NeedsReauth`) with zero retry storm.
 */
class CloudAuthCoordinator(
  private val vault: CredentialVault,
  val tokenEndpoint: OAuthTokenEndpointAdapter = HttpsOAuthTokenEndpointAdapter(),
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
) {
  private val rng = SecureRandom()
  private val pendingRequestsByState = ConcurrentHashMap<String, PkceAuthRequest>()
  private val refreshMutexByAccount = ConcurrentHashMap<VaultKey, Mutex>()
  private val cachedAccessTokens = ConcurrentHashMap<VaultKey, CachedAccessToken>()
  private val reauthRequiredAccounts = ConcurrentHashMap.newKeySet<VaultKey>()

  val isSimulatedEndpoint: Boolean
    get() = tokenEndpoint.isSimulatedEndpoint

  private data class CachedAccessToken(
    val tokenBytes: ByteArray,
    val expiresAtEpochMillis: Long,
  )

  fun startSystemBrowserPkceFlow(
    provider: StorageProvider,
    publicClientId: String,
    fullAccessOptIn: Boolean = false,
  ): StorageResult<PkceAuthRequest> {
    if (publicClientId.isBlank() || publicClientId.startsWith("PLACEHOLDER_")) {
      return StorageResult.Failure(
        StorageError.AUTH_REQUIRED,
        "Configure OAuth public Client ID for $provider in AI Studio Secrets / local.properties"
      )
    }
    val verifierRaw = ByteArray(32).also { rng.nextBytes(it) }
    val verifierStr = Base64.getUrlEncoder().withoutPadding().encodeToString(verifierRaw)
    val challengeBytes = MessageDigest.getInstance("SHA-256").digest(verifierStr.encodeToByteArray())
    val challengeS256 = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes)

    val stateBytes = ByteArray(16).also { rng.nextBytes(it) }
    val state = Base64.getUrlEncoder().withoutPadding().encodeToString(stateBytes)
    val scopes = CloudProviderScopes.defaultScopes(provider, fullAccessOptIn)

    val authEndpoint = when (provider) {
      StorageProvider.GOOGLE_DRIVE -> "https://accounts.google.com/o/oauth2/v2/auth"
      StorageProvider.ONEDRIVE -> "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
      StorageProvider.DROPBOX -> "https://www.dropbox.com/oauth2/authorize"
      else -> return StorageResult.Failure(StorageError.UNSUPPORTED, "Not a cloud provider: $provider")
    }

    val url = "$authEndpoint?response_type=code&client_id=$publicClientId" +
      "&redirect_uri=${CloudProviderScopes.REDIRECT_URI}" +
      "&code_challenge=$challengeS256&code_challenge_method=S256" +
      "&state=$state&scope=${scopes.joinToString("%20")}"

    val req = PkceAuthRequest(
      provider = provider,
      publicClientId = publicClientId,
      redirectUri = CloudProviderScopes.REDIRECT_URI,
      state = state,
      codeVerifier = SecretBytes(verifierStr.encodeToByteArray()),
      codeChallengeS256 = challengeS256,
      scopes = scopes,
      systemBrowserAuthorizationUrl = url,
    )
    pendingRequestsByState[state] = req
    return StorageResult.Success(req)
  }

  suspend fun completeRedirectCallback(
    accountVaultKey: VaultKey,
    receivedRedirectUri: String,
    receivedState: String,
    authorizationCode: String,
  ): StorageResult<Unit> {
    if (receivedRedirectUri != CloudProviderScopes.REDIRECT_URI) {
      return StorageResult.Failure(StorageError.DENIED, "OAuth redirect URI mismatch")
    }
    val pending = pendingRequestsByState.remove(receivedState)
      ?: return StorageResult.Failure(StorageError.DENIED, "Unknown or replayed OAuth state parameter")
    if (authorizationCode.isBlank()) {
      pending.codeVerifier.close()
      return StorageResult.Failure(StorageError.DENIED, "Empty authorization code")
    }

    val response = pending.codeVerifier.useBytes { verifierBytes ->
      tokenEndpoint.exchangeCodeWithPkce(
        provider = pending.provider,
        publicClientId = pending.publicClientId,
        redirectUri = pending.redirectUri,
        authorizationCode = authorizationCode,
        codeVerifierBytes = verifierBytes,
      )
    }

    if (response.outcome != TokenRefreshOutcome.SUCCESS ||
      response.accessTokenBytes == null ||
      response.refreshTokenBytes == null
    ) {
      return StorageResult.Failure(StorageError.AUTH_REQUIRED, "OAuth code exchange failed")
    }

    val saveRes = vault.put(accountVaultKey, SecretBytes(response.refreshTokenBytes))
    if (saveRes is StorageResult.Failure) return saveRes

    reauthRequiredAccounts.remove(accountVaultKey)
    cachedAccessTokens[accountVaultKey] = CachedAccessToken(
      tokenBytes = response.accessTokenBytes.copyOf(),
      expiresAtEpochMillis = clockEpochMillis() + (response.expiresInSeconds * 1000L) - 30_000L,
    )
    return StorageResult.Success(Unit)
  }

  /**
   * Single-flight access token getter & proactive refresher (§8.8, §13).
   * If a refresh previously failed with `invalid_grant`, immediately returns `AUTH_REQUIRED` without hitting the network.
   */
  suspend fun getValidAccessToken(
    accountVaultKey: VaultKey,
    provider: StorageProvider,
    publicClientId: String,
  ): StorageResult<SecretBytes> {
    if (accountVaultKey in reauthRequiredAccounts) {
      return StorageResult.Failure(
        StorageError.AUTH_REQUIRED,
        "Account requires user re-authentication (NEEDS_REAUTH)"
      )
    }

    val now = clockEpochMillis()
    val fastCached = cachedAccessTokens[accountVaultKey]
    if (fastCached != null && now < fastCached.expiresAtEpochMillis) {
      return StorageResult.Success(SecretBytes(fastCached.tokenBytes.copyOf()))
    }

    val mutex = refreshMutexByAccount.getOrPut(accountVaultKey) { Mutex() }
    return mutex.withLock {
      if (accountVaultKey in reauthRequiredAccounts) {
        return@withLock StorageResult.Failure(
          StorageError.AUTH_REQUIRED,
          "Account requires user re-authentication (NEEDS_REAUTH)"
        )
      }
      val recheckNow = clockEpochMillis()
      val secondCached = cachedAccessTokens[accountVaultKey]
      if (secondCached != null && recheckNow < secondCached.expiresAtEpochMillis) {
        return@withLock StorageResult.Success(SecretBytes(secondCached.tokenBytes.copyOf()))
      }

      val refreshRes = vault.get(accountVaultKey)
      if (refreshRes is StorageResult.Failure) return@withLock refreshRes
      val refreshSecret = (refreshRes as StorageResult.Success).value
        ?: return@withLock StorageResult.Failure(StorageError.AUTH_REQUIRED, "Missing refresh token in vault")

      val exchange = refreshSecret.useBytes { refreshBytes ->
        tokenEndpoint.refreshAccessToken(provider, publicClientId, refreshBytes)
      }
      when (exchange.outcome) {
        TokenRefreshOutcome.SUCCESS -> {
          val newAccess = exchange.accessTokenBytes
            ?: return@withLock StorageResult.Failure(StorageError.INTERNAL, "Empty refreshed access token")
          exchange.refreshTokenBytes?.let { rotated ->
            vault.put(accountVaultKey, SecretBytes(rotated))
          }
          cachedAccessTokens[accountVaultKey] = CachedAccessToken(
            tokenBytes = newAccess.copyOf(),
            expiresAtEpochMillis = recheckNow + (exchange.expiresInSeconds * 1000L) - 30_000L,
          )
          StorageResult.Success(SecretBytes(newAccess.copyOf()))
        }
        TokenRefreshOutcome.INVALID_GRANT_REVOKED -> {
          // Latch NEEDS_REAUTH so we never cause a retry storm (§8.8, §11)
          reauthRequiredAccounts.add(accountVaultKey)
          cachedAccessTokens.remove(accountVaultKey)?.tokenBytes?.fill(0)
          StorageResult.Failure(StorageError.AUTH_REQUIRED, "OAuth refresh token revoked or expired (NEEDS_REAUTH)")
        }
        TokenRefreshOutcome.RATE_LIMITED ->
          StorageResult.Failure(StorageError.RATE_LIMITED, "OAuth token endpoint rate-limited (429)")
        TokenRefreshOutcome.NETWORK_UNAVAILABLE ->
          StorageResult.Failure(StorageError.UNAVAILABLE, "Cloud OAuth endpoint unreachable")
      }
    }
  }

  suspend fun unlinkAccountAndRevoke(
    accountVaultKey: VaultKey,
    provider: StorageProvider,
  ): StorageResult<Unit> {
    reauthRequiredAccounts.remove(accountVaultKey)
    cachedAccessTokens.remove(accountVaultKey)?.tokenBytes?.fill(0)
    val stored = vault.get(accountVaultKey).getOrNull()
    stored?.useBytes { refreshBytes ->
      runCatching { tokenEndpoint.revokeTokenAtProvider(provider, refreshBytes) }
    }
    return vault.delete(accountVaultKey)
  }
}

data class CloudItemNode(
  val itemId: String,
  val parentItemId: String?,
  val name: String,
  val isFolder: Boolean,
  val mimeType: String = "application/octet-stream",
  var bytes: ByteArray = ByteArray(0),
  var lastModifiedEpochMillis: Long = 1_700_000_000_000L,
)

/**
 * ID-based Cloud Storage backend (Google Drive v3, Microsoft Graph OneDrive, Dropbox v2) (§8.8).
 * Backends resolve [SafePath] segment-by-segment by name under `rootFolderId` and never trust client-supplied provider IDs.
 * Explicitly reports `isRestWireStubbed = true` so the UI displays a SIMULATION warning banner when active.
 */
class CloudIdTreeBackend(
  val provider: StorageProvider,
  private val accountVaultKey: VaultKey,
  private val publicClientId: String,
  private val rootFolderId: String,
  private val authCoordinator: CloudAuthCoordinator,
  override val isReadOnly: Boolean = false,
  val enforceOneDrive320KiBChunkAlignment: Boolean = (provider == StorageProvider.ONEDRIVE),
) : FileBackend {

  val isRestWireStubbed: Boolean = true
  private val itemsById = ConcurrentHashMap<String, CloudItemNode>()
  private var nextId = 100
  var simulatedHttpStatus: Int = 200

  init {
    itemsById[rootFolderId] = CloudItemNode(
      itemId = rootFolderId,
      parentItemId = null,
      name = "/",
      isFolder = true,
    )
  }

  fun injectItemForTesting(node: CloudItemNode) {
    itemsById[node.itemId] = node
  }

  private suspend fun checkAuthAndStatus(): StorageResult<Unit> {
    val tokenRes = authCoordinator.getValidAccessToken(accountVaultKey, provider, publicClientId)
    if (tokenRes is StorageResult.Failure) return tokenRes
    (tokenRes as StorageResult.Success).value.close()

    return when (simulatedHttpStatus) {
      200, 201, 204 -> StorageResult.Success(Unit)
      401 -> StorageResult.Failure(StorageError.AUTH_REQUIRED, "$provider returned 401 Unauthorized")
      403 -> StorageResult.Failure(StorageError.DENIED, "$provider returned 403 Forbidden")
      429 -> StorageResult.Failure(StorageError.RATE_LIMITED, "$provider returned 429 Too Many Requests (Retry-After)")
      503 -> StorageResult.Failure(StorageError.UNAVAILABLE, "$provider service unavailable")
      else -> StorageResult.Failure(StorageError.INTERNAL, "$provider HTTP $simulatedHttpStatus")
    }
  }

  private fun resolveByIdHopByHop(path: SafePath): StorageResult<CloudItemNode> {
    val root = itemsById[rootFolderId]
      ?: return StorageResult.Failure(StorageError.NOT_FOUND, "Cloud root folder missing")
    if (path.isRoot) return StorageResult.Success(root)

    var current = root
    for (seg in path.segments) {
      if (!current.isFolder) {
        return StorageResult.Failure(StorageError.NOT_FOUND, "Parent is not a folder")
      }
      val children = itemsById.values.filter { it.parentItemId == current.itemId && it.name == seg }
      if (children.size > 1) {
        return StorageResult.Failure(
          StorageError.DUPLICATE_NAME,
          "$provider folder contains duplicate items named '$seg' (§8.8)"
        )
      }
      current = children.firstOrNull()
        ?: return StorageResult.Failure(StorageError.NOT_FOUND, "Cloud item not found: $seg")
    }
    return StorageResult.Success(current)
  }

  override suspend fun list(path: SafePath, pageSize: Int, pageToken: String?): StorageResult<ListPage> {
    val auth = checkAuthAndStatus()
    if (auth is StorageResult.Failure) return auth
    val resolved = resolveByIdHopByHop(path)
    if (resolved is StorageResult.Failure) return resolved
    val folder = (resolved as StorageResult.Success).value
    if (!folder.isFolder) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Not a cloud folder")
    }
    val children = itemsById.values.filter { it.parentItemId == folder.itemId }
    val names = children.map { it.name }
    if (names.size != names.distinct().size) {
      return StorageResult.Failure(StorageError.DUPLICATE_NAME, "Duplicate filenames in $provider folder")
    }
    val entries = children.sortedBy { it.name }.map {
      FileEntry(
        name = it.name,
        isDirectory = it.isFolder,
        sizeBytes = it.bytes.size.toLong(),
        lastModifiedEpochMillis = it.lastModifiedEpochMillis,
      )
    }
    return StorageResult.Success(ListPage(entries = entries, nextPageToken = null))
  }

  override suspend fun stat(path: SafePath): StorageResult<FileStat> {
    val auth = checkAuthAndStatus()
    if (auth is StorageResult.Failure) return auth
    val resolved = resolveByIdHopByHop(path)
    if (resolved is StorageResult.Failure) return resolved
    val node = (resolved as StorageResult.Success).value
    if (provider == StorageProvider.GOOGLE_DRIVE && node.mimeType.startsWith("application/vnd.google-apps.")) {
      return StorageResult.Failure(
        StorageError.UNSUPPORTED,
        "Google-native document (${node.mimeType}) is not a raw byte file (§8.8)"
      )
    }
    return StorageResult.Success(
      FileStat(
        name = node.name,
        isDirectory = node.isFolder,
        sizeBytes = node.bytes.size.toLong(),
        lastModifiedEpochMillis = node.lastModifiedEpochMillis,
      )
    )
  }

  override fun open(path: SafePath, offset: Long, length: Long): Flow<ByteArray> = flow {
    val auth = checkAuthAndStatus()
    if (auth is StorageResult.Failure) throw StorageException(auth.error, auth.message)
    val resolved = resolveByIdHopByHop(path)
    if (resolved is StorageResult.Failure) throw StorageException(resolved.error, resolved.message)
    val node = (resolved as StorageResult.Success).value
    if (node.isFolder) throw StorageException(StorageError.PATH_INVALID, "Cannot open folder")
    if (provider == StorageProvider.GOOGLE_DRIVE && node.mimeType.startsWith("application/vnd.google-apps.")) {
      throw StorageException(StorageError.UNSUPPORTED, "Google-native doc cannot be streamed as raw bytes")
    }
    val bytes = node.bytes
    var cursor = offset.toInt().coerceAtMost(bytes.size)
    val end = min(bytes.size.toLong(), if (Long.MAX_VALUE - offset < length) bytes.size.toLong() else offset + length).toInt()
    while (cursor < end) {
      currentCoroutineContext().ensureActive()
      val next = min(end, cursor + FileBackend.CHUNK_SIZE_BYTES)
      emit(bytes.copyOfRange(cursor, next))
      cursor = next
    }
  }

  override suspend fun write(
    path: SafePath,
    mode: WriteMode,
    data: Flow<ByteArray>,
    expectedSize: Long?,
  ): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "Cloud mount is read-only")
    if (path.isRoot) return StorageResult.Failure(StorageError.PATH_INVALID, "Cannot write root")
    val auth = checkAuthAndStatus()
    if (auth is StorageResult.Failure) return auth

    val parentRes = resolveByIdHopByHop(path.parent ?: SafePath.ROOT)
    if (parentRes is StorageResult.Failure) return parentRes
    val parent = (parentRes as StorageResult.Success).value

    val buffer = ByteArrayOutputStream()
    val chunkSizes = mutableListOf<Int>()
    data.collect { chunk ->
      currentCoroutineContext().ensureActive()
      chunkSizes.add(chunk.size)
      buffer.write(chunk)
    }
    val assembled = rebufferForProviderUploadSession(buffer.toByteArray())
    if (expectedSize != null && expectedSize != assembled.size.toLong()) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Upload size mismatch")
    }

    val existing = itemsById.values.filter { it.parentItemId == parent.itemId && it.name == path.name }
    if (existing.size > 1) {
      return StorageResult.Failure(StorageError.DUPLICATE_NAME, "Duplicate target '${path.name}'")
    }
    val node = if (existing.isNotEmpty()) {
      if (mode == WriteMode.CREATE_NEW) {
        return StorageResult.Failure(StorageError.EXISTS, "Cloud file already exists")
      }
      existing.first().also { it.bytes = assembled }
    } else {
      val id = "${provider.name.lowercase()}_${nextId++}"
      CloudItemNode(
        itemId = id,
        parentItemId = parent.itemId,
        name = path.name,
        isFolder = false,
        bytes = assembled,
      ).also { itemsById[id] = it }
    }

    return StorageResult.Success(
      FileStat(
        name = node.name,
        isDirectory = false,
        sizeBytes = node.bytes.size.toLong(),
        lastModifiedEpochMillis = node.lastModifiedEpochMillis,
      )
    )
  }

  /**
   * Ensures OneDrive Graph upload session chunks are sliced in 320 KiB (`327_680` byte) multiples (§8.8).
   */
  internal fun sliceForOneDriveUploadSession(raw: ByteArray): List<ByteArray> {
    val unit = ONEDRIVE_CHUNK_ALIGNMENT_BYTES
    if (raw.isEmpty()) return listOf(ByteArray(0))
    val slices = mutableListOf<ByteArray>()
    var offset = 0
    while (offset < raw.size) {
      val end = min(raw.size, offset + unit)
      slices.add(raw.copyOfRange(offset, end))
      offset = end
    }
    return slices
  }

  private fun rebufferForProviderUploadSession(raw: ByteArray): ByteArray {
    if (!enforceOneDrive320KiBChunkAlignment) return raw
    val slices = sliceForOneDriveUploadSession(raw)
    val out = ByteArrayOutputStream(raw.size)
    for ((idx, slice) in slices.withIndex()) {
      if (idx < slices.lastIndex) {
        check(slice.size % ONEDRIVE_CHUNK_ALIGNMENT_BYTES == 0) {
          "OneDrive intermediate chunk must be a multiple of 320 KiB"
        }
      }
      out.write(slice)
    }
    return out.toByteArray()
  }

  override suspend fun mkdir(path: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "Cloud mount is read-only")
    val auth = checkAuthAndStatus()
    if (auth is StorageResult.Failure) return auth
    val parentRes = resolveByIdHopByHop(path.parent ?: SafePath.ROOT)
    if (parentRes is StorageResult.Failure) return parentRes
    val parent = (parentRes as StorageResult.Success).value
    if (itemsById.values.any { it.parentItemId == parent.itemId && it.name == path.name }) {
      return StorageResult.Failure(StorageError.EXISTS, "Folder exists")
    }
    val id = "${provider.name.lowercase()}_dir_${nextId++}"
    val dir = CloudItemNode(id, parent.itemId, path.name, isFolder = true)
    itemsById[id] = dir
    return StorageResult.Success(FileStat(dir.name, true, 0L, dir.lastModifiedEpochMillis))
  }

  override suspend fun delete(path: SafePath, recursive: Boolean): StorageResult<Unit> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "Cloud mount is read-only")
    val auth = checkAuthAndStatus()
    if (auth is StorageResult.Failure) return auth
    val targetRes = resolveByIdHopByHop(path)
    if (targetRes is StorageResult.Failure) return targetRes
    val target = (targetRes as StorageResult.Success).value
    itemsById.remove(target.itemId)
    return StorageResult.Success(Unit)
  }

  override suspend fun move(src: SafePath, dst: SafePath): StorageResult<FileStat> {
    if (isReadOnly) return StorageResult.Failure(StorageError.DENIED, "Cloud mount is read-only")
    val auth = checkAuthAndStatus()
    if (auth is StorageResult.Failure) return auth
    val srcRes = resolveByIdHopByHop(src)
    if (srcRes is StorageResult.Failure) return srcRes
    val srcNode = (srcRes as StorageResult.Success).value
    val dstParentRes = resolveByIdHopByHop(dst.parent ?: SafePath.ROOT)
    if (dstParentRes is StorageResult.Failure) return dstParentRes
    val dstParent = (dstParentRes as StorageResult.Success).value
    val updated = srcNode.copy(parentItemId = dstParent.itemId, name = dst.name)
    itemsById[updated.itemId] = updated
    return StorageResult.Success(
      FileStat(updated.name, updated.isFolder, updated.bytes.size.toLong(), updated.lastModifiedEpochMillis)
    )
  }

  companion object {
    const val ONEDRIVE_CHUNK_ALIGNMENT_BYTES = 320 * 1024 // 320 KiB exact alignment required by Microsoft Graph (§8.8)
  }
}
