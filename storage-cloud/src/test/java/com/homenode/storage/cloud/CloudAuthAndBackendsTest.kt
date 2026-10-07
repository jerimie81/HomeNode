package com.homenode.storage.cloud

import com.homenode.core.storage.InMemoryCredentialVault
import com.homenode.core.storage.PathValidator
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
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudAuthAndBackendsTest {

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

    // OneDrive 320 KiB upload chunk alignment verification
    val oneDrive = CloudIdTreeBackend(
      provider = StorageProvider.ONEDRIVE,
      accountVaultKey = key,
      publicClientId = clientId,
      rootFolderId = "od_root",
      authCoordinator = auth,
    )
    val payload700KiB = ByteArray(700 * 1024) { (it and 0x7F).toByte() }
    val slices = oneDrive.sliceForOneDriveUploadSession(payload700KiB)
    assertEquals(3, slices.size)
    assertEquals(320 * 1024, slices[0].size)
    assertEquals(320 * 1024, slices[1].size)
    assertEquals(60 * 1024, slices[2].size)

    val odFile = PathValidator.parseRelative("backup.tar").getOrThrow()
    assertTrue(oneDrive.write(odFile, WriteMode.OVERWRITE, flowOf(payload700KiB), payload700KiB.size.toLong()).isSuccess)
  }
}
