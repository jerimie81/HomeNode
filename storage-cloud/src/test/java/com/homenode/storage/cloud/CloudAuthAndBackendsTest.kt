package com.homenode.storage.cloud

import com.homenode.core.storage.InMemoryCredentialVault
import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.PathValidator
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import com.homenode.core.storage.WriteMode
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudAuthAndBackendsTest {

  @Test
  fun oauthPkce_capsPendingRequestsAndExpiresAbandonedState() = runTest {
    var now = 10_000L
    val endpoint = object : OAuthTokenEndpointAdapter {
      override suspend fun exchangeCodeWithPkce(
        provider: StorageProvider,
        publicClientId: String,
        redirectUri: String,
        authorizationCode: String,
        codeVerifierBytes: ByteArray,
      ) = TokenExchangeResponse(TokenRefreshOutcome.SUCCESS, byteArrayOf(1), byteArrayOf(2), 3600L)

      override suspend fun refreshAccessToken(
        provider: StorageProvider,
        publicClientId: String,
        refreshTokenBytes: ByteArray,
      ) = TokenExchangeResponse(TokenRefreshOutcome.SUCCESS, byteArrayOf(1), byteArrayOf(2), 3600L)

      override suspend fun revokeTokenAtProvider(provider: StorageProvider, tokenBytes: ByteArray) = true
    }
    val auth = CloudAuthCoordinator(InMemoryCredentialVault(), endpoint) { now }
    val requests = (1..8).map {
      auth.startSystemBrowserPkceFlow(StorageProvider.GOOGLE_DRIVE, "client").getOrThrow()
    }
    assertEquals(StorageError.QUOTA, (auth.startSystemBrowserPkceFlow(
      StorageProvider.GOOGLE_DRIVE, "client",
    ) as StorageResult.Failure).error)

    now += 5 * 60 * 1000L
    assertTrue(
      auth.completeRedirectCallback(
        VaultKey("expired.pkce"), CloudProviderScopes.REDIRECT_URI, requests.first().state, "code",
      ).isFailure
    )
    assertTrue(auth.startSystemBrowserPkceFlow(StorageProvider.GOOGLE_DRIVE, "client").isSuccess)
  }

  @Test
  fun oauthPkce_encodesAuthorizationParametersAndFailsClosedWhenRotationCannotPersist() = runTest {
    val backing = InMemoryCredentialVault()
    var putCount = 0
    val vault = object : CredentialVault {
      override suspend fun put(key: VaultKey, secret: SecretBytes): StorageResult<Unit> {
        putCount++
        return if (putCount == 1) backing.put(key, secret) else {
          secret.close()
          StorageResult.Failure(StorageError.INTERNAL, "simulated vault write failure")
        }
      }

      override suspend fun get(key: VaultKey) = backing.get(key)
      override suspend fun delete(key: VaultKey) = backing.delete(key)
      override suspend fun wipeAll() = backing.wipeAll()
    }
    var now = 1_000L
    val endpoint = object : OAuthTokenEndpointAdapter {
      override suspend fun exchangeCodeWithPkce(
        provider: StorageProvider,
        publicClientId: String,
        redirectUri: String,
        authorizationCode: String,
        codeVerifierBytes: ByteArray,
      ) = TokenExchangeResponse(
        TokenRefreshOutcome.SUCCESS,
        "access-1".encodeToByteArray(),
        "refresh-1".encodeToByteArray(),
        60L,
      )

      override suspend fun refreshAccessToken(
        provider: StorageProvider,
        publicClientId: String,
        refreshTokenBytes: ByteArray,
      ) = TokenExchangeResponse(
        TokenRefreshOutcome.SUCCESS,
        "access-2".encodeToByteArray(),
        "refresh-2".encodeToByteArray(),
        60L,
      )

      override suspend fun revokeTokenAtProvider(provider: StorageProvider, tokenBytes: ByteArray) = true
    }
    val auth = CloudAuthCoordinator(vault, endpoint) { now }
    val key = VaultKey("cloud.rotation.failure")
    val request = auth.startSystemBrowserPkceFlow(
      StorageProvider.GOOGLE_DRIVE,
      "client&injected=value",
    ).getOrThrow()
    assertTrue(request.systemBrowserAuthorizationUrl.contains("client_id=client%26injected%3Dvalue"))
    assertTrue(
      auth.completeRedirectCallback(key, CloudProviderScopes.REDIRECT_URI, request.state, "code").isSuccess
    )

    now += 61_000L
    val refresh = auth.getValidAccessToken(key, StorageProvider.GOOGLE_DRIVE, "client&injected=value")
    assertEquals(StorageError.AUTH_REQUIRED, (refresh as StorageResult.Failure).error)
    val repeat = auth.getValidAccessToken(key, StorageProvider.GOOGLE_DRIVE, "client&injected=value")
    assertEquals(StorageError.AUTH_REQUIRED, (repeat as StorageResult.Failure).error)
  }

  @Test
  fun oauthPkce_enforcesStateRedirectSingleFlightRefreshAndNoRetryStormOnRevocation() = runTest {
    var now = 1_000_000L
    val vault = InMemoryCredentialVault()
    val refreshCallCount = AtomicInteger(0)
    var nextRefreshOutcome = TokenRefreshOutcome.SUCCESS

    val fakeEndpoint = object : OAuthTokenEndpointAdapter {
      override suspend fun exchangeCodeWithPkce(
        provider: StorageProvider,
        publicClientId: String,
        redirectUri: String,
        authorizationCode: String,
        codeVerifierBytes: ByteArray,
      ): TokenExchangeResponse = TokenExchangeResponse(
        outcome = TokenRefreshOutcome.SUCCESS,
        accessTokenBytes = "initial-access-token".encodeToByteArray(),
        refreshTokenBytes = "initial-refresh-token".encodeToByteArray(),
        expiresInSeconds = 60L,
      )

      override suspend fun refreshAccessToken(
        provider: StorageProvider,
        publicClientId: String,
        refreshTokenBytes: ByteArray,
      ): TokenExchangeResponse {
        refreshCallCount.incrementAndGet()
        delay(20)
        return TokenExchangeResponse(
          outcome = nextRefreshOutcome,
          accessTokenBytes = "refreshed-access-${refreshCallCount.get()}".encodeToByteArray(),
          refreshTokenBytes = refreshTokenBytes,
          expiresInSeconds = 3600L,
        )
      }

      override suspend fun revokeTokenAtProvider(
        provider: StorageProvider,
        tokenBytes: ByteArray,
      ): Boolean = true
    }

    val auth = CloudAuthCoordinator(vault, fakeEndpoint) { now }
    val accountKey = VaultKey("cloud.gdrive.acc1")
    val clientId = "123456-gdrive-client.apps.googleusercontent.com"

    val pkceReq = auth.startSystemBrowserPkceFlow(StorageProvider.GOOGLE_DRIVE, clientId).getOrThrow()
    assertTrue(pkceReq.systemBrowserAuthorizationUrl.contains("code_challenge_method=S256"))
    assertEquals(listOf("https://www.googleapis.com/auth/drive.file"), pkceReq.scopes)

    // Wrong state or wrong redirect URI must fail
    assertTrue(
      auth.completeRedirectCallback(
        accountVaultKey = accountKey,
        receivedRedirectUri = "https://evil.example.com/cb",
        receivedState = pkceReq.state,
        authorizationCode = "code123",
      ).isFailure
    )
    assertTrue(
      auth.completeRedirectCallback(
        accountVaultKey = accountKey,
        receivedRedirectUri = CloudProviderScopes.REDIRECT_URI,
        receivedState = "wrong-state",
        authorizationCode = "code123",
      ).isFailure
    )

    // Valid callback succeeds
    assertTrue(
      auth.completeRedirectCallback(
        accountVaultKey = accountKey,
        receivedRedirectUri = CloudProviderScopes.REDIRECT_URI,
        receivedState = pkceReq.state,
        authorizationCode = "code123",
      ).isSuccess
    )

    // Advance clock past initial access token expiry and launch 8 concurrent token requests -> single-flight refresh!
    now += 65_000L
    val results = (1..8).map {
      async { auth.getValidAccessToken(accountKey, StorageProvider.GOOGLE_DRIVE, clientId) }
    }.awaitAll()
    assertTrue(results.all { it.isSuccess })
    results.forEach { it.getOrNull()?.close() }
    assertEquals("Single-flight mutex must coalesce concurrent refreshes into 1 call", 1, refreshCallCount.get())

    // Simulate token revocation (`invalid_grant`) -> latches NEEDS_REAUTH and prevents retry storms
    now += 4_000_000L
    nextRefreshOutcome = TokenRefreshOutcome.INVALID_GRANT_REVOKED
    val fail1 = auth.getValidAccessToken(accountKey, StorageProvider.GOOGLE_DRIVE, clientId)
    assertEquals(StorageError.AUTH_REQUIRED, (fail1 as StorageResult.Failure).error)
    val callsAfterRevoke = refreshCallCount.get()

    // Subsequent calls return AUTH_REQUIRED immediately without hitting the token endpoint
    val fail2 = auth.getValidAccessToken(accountKey, StorageProvider.GOOGLE_DRIVE, clientId)
    assertEquals(StorageError.AUTH_REQUIRED, (fail2 as StorageResult.Failure).error)
    assertEquals("Must not retry network refresh after invalid_grant", callsAfterRevoke, refreshCallCount.get())
  }

  @Test
  fun cloudBackends_handleDriveDuplicatesGoogleDocsOneDrive320KiBAlignmentAnd429() = runTest {
    val vault = InMemoryCredentialVault()
    val fakeEndpoint = object : OAuthTokenEndpointAdapter {
      override suspend fun exchangeCodeWithPkce(
        provider: StorageProvider,
        publicClientId: String,
        redirectUri: String,
        authorizationCode: String,
        codeVerifierBytes: ByteArray,
      ) = TokenExchangeResponse(
        TokenRefreshOutcome.SUCCESS,
        "tok".encodeToByteArray(),
        "ref".encodeToByteArray(),
        3600L,
      )

      override suspend fun refreshAccessToken(
        provider: StorageProvider,
        publicClientId: String,
        refreshTokenBytes: ByteArray,
      ) = TokenExchangeResponse(TokenRefreshOutcome.SUCCESS, "tok".encodeToByteArray(), refreshTokenBytes, 3600L)

      override suspend fun revokeTokenAtProvider(provider: StorageProvider, tokenBytes: ByteArray) = true
    }

    val auth = CloudAuthCoordinator(vault, fakeEndpoint)
    val key = VaultKey("cloud.acc")
    val clientId = "client-id-1"
    val req = auth.startSystemBrowserPkceFlow(StorageProvider.GOOGLE_DRIVE, clientId).getOrThrow()
    auth.completeRedirectCallback(key, CloudProviderScopes.REDIRECT_URI, req.state, "c1")

    val drive = CloudIdTreeBackend(
      provider = StorageProvider.GOOGLE_DRIVE,
      accountVaultKey = key,
      publicClientId = clientId,
      rootFolderId = "root",
      authCoordinator = auth,
    )

    // Google Docs native mimeType must return UNSUPPORTED
    drive.injectItemForTesting(
      CloudItemNode(
        itemId = "gdoc1",
        parentItemId = "root",
        name = "BudgetSheet",
        isFolder = false,
        mimeType = "application/vnd.google-apps.spreadsheet",
      )
    )
    val gdocPath = PathValidator.parseRelative("BudgetSheet").getOrThrow()
    assertEquals(StorageError.UNSUPPORTED, (drive.stat(gdocPath) as StorageResult.Failure).error)

    // HTTP 429 maps to RATE_LIMITED
    drive.simulatedHttpStatus = 429
    assertEquals(StorageError.RATE_LIMITED, (drive.list(PathValidator.parseRelative("").getOrThrow()) as StorageResult.Failure).error)
    drive.simulatedHttpStatus = 200

    // OneDrive 320 KiB upload session behavior is covered by OneDriveAdapterTest.
    val oneDrive = CloudIdTreeBackend(
      provider = StorageProvider.ONEDRIVE,
      accountVaultKey = key,
      publicClientId = clientId,
      rootFolderId = "od_root",
      authCoordinator = auth,
      uploadRegistry = CloudUploadRegistry(mapOf(
        CloudProvider.ONEDRIVE to InMemoryUploadAdapter(provider = CloudProvider.ONEDRIVE),
      )),
    )
    val payload700KiB = ByteArray(700 * 1024) { (it and 0x7F).toByte() }
    val odFile = PathValidator.parseRelative("backup.tar").getOrThrow()
    assertTrue(oneDrive.write(odFile, WriteMode.OVERWRITE, flowOf(payload700KiB), payload700KiB.size.toLong()).isSuccess)
    assertEquals(payload700KiB.size.toLong(), oneDrive.stat(odFile).getOrThrow().sizeBytes)

    val unavailableBackend = CloudIdTreeBackend(
      provider = StorageProvider.DROPBOX,
      accountVaultKey = key,
      publicClientId = clientId,
      rootFolderId = "db_root",
      authCoordinator = auth,
      uploadRegistry = CloudUploadRegistry(emptyMap()),
    )
    val unavailableWrite = unavailableBackend.write(
      PathValidator.parseRelative("no-adapter.bin").getOrThrow(),
      WriteMode.CREATE_NEW,
      flow { error("Fail-closed registry must reject before reading the request body") },
      1L,
    )
    assertEquals(StorageError.UNAVAILABLE, (unavailableWrite as StorageResult.Failure).error)
  }
}
