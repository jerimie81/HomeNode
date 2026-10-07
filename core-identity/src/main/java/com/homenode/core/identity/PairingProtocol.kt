package com.homenode.core.identity

import com.homenode.core.storage.Capability
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Validated pairing QR payload (`homenode://pair?v=1&...`) (§5, Slice S17).
 * Never contains private keys, passwords, or OAuth tokens.
 */
data class PairingPayload(
  val version: Int,
  val nodeId: String,
  val publicKey: PeerId,
  val endpointHints: List<String>,
  val singleUseToken: String,
  val expiresAtEpochMillis: Long,
)

sealed interface PairingResult<out T> {
  data class Success<T>(val value: T) : PairingResult<T>
  data class Failure(val reason: String) : PairingResult<Nothing>

  val isSuccess: Boolean get() = this is Success
  val isFailure: Boolean get() = this is Failure
}

object PairingPayloadParser {
  const val MAX_URI_LENGTH = 512
  const val SUPPORTED_VERSION = 1
  private val ALLOWED_KEYS = setOf("v", "node", "pub", "ep", "tok", "exp")
  private val FORBIDDEN_SECRET_KEYS = setOf("priv", "private_key", "secret", "password", "oauth_token", "refresh_token")
  private val NODE_ID_REGEX = Regex("^[a-zA-Z0-9_-]{4,40}$")
  private val ENDPOINT_HINT_REGEX = Regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}:[0-9]{1,5}$")

  fun parse(rawUri: String, nowEpochMillis: Long = System.currentTimeMillis()): PairingResult<PairingPayload> {
    if (rawUri.isEmpty() || rawUri.length > MAX_URI_LENGTH) {
      return PairingResult.Failure("Pairing URI length out of bounds")
    }
    if (!rawUri.startsWith("homenode://pair?")) {
      return PairingResult.Failure("Invalid scheme or host; expected homenode://pair?")
    }
    val query = rawUri.removePrefix("homenode://pair?")
    if (query.isEmpty() || query.contains('#')) {
      return PairingResult.Failure("Invalid query string")
    }

    val params = mutableMapOf<String, String>()
    for (part in query.split('&')) {
      val eqIdx = part.indexOf('=')
      if (eqIdx <= 0 || eqIdx == part.lastIndex) {
        return PairingResult.Failure("Malformed query parameter")
      }
      val key = part.substring(0, eqIdx)
      val value = part.substring(eqIdx + 1)
      if (key.lowercase() in FORBIDDEN_SECRET_KEYS) {
        return PairingResult.Failure("Secret fields are strictly forbidden in pairing QR payloads")
      }
      if (key !in ALLOWED_KEYS) {
        return PairingResult.Failure("Unknown pairing parameter '$key'")
      }
      if (params.containsKey(key)) {
        return PairingResult.Failure("Duplicate pairing parameter '$key'")
      }
      params[key] = value
    }

    val version = params["v"]?.toIntOrNull()
      ?: return PairingResult.Failure("Missing or non-integer version 'v'")
    if (version != SUPPORTED_VERSION) {
      return PairingResult.Failure("Unsupported pairing protocol version: $version")
    }

    val nodeId = params["node"] ?: return PairingResult.Failure("Missing 'node'")
    if (!NODE_ID_REGEX.matches(nodeId)) {
      return PairingResult.Failure("Invalid node ID format")
    }

    val pubRaw = params["pub"] ?: return PairingResult.Failure("Missing 'pub'")
    val publicKey = PeerId.parse(pubRaw)
      ?: return PairingResult.Failure("Invalid 32-byte base64url public key")

    val tokRaw = params["tok"] ?: return PairingResult.Failure("Missing single-use token 'tok'")
    val tokenBytes = try {
      Base64.getUrlDecoder().decode(tokRaw)
    } catch (e: Exception) {
      return PairingResult.Failure("Invalid base64url token")
    }
    if (tokenBytes.size < 16) { // >= 128-bit random required (§5)
      return PairingResult.Failure("Pairing token must be at least 128 bits")
    }

    val expMillis = params["exp"]?.toLongOrNull()
      ?: return PairingResult.Failure("Missing or invalid expiry 'exp'")
    if (expMillis <= nowEpochMillis) {
      return PairingResult.Failure("Pairing QR payload has expired")
    }
    if (expMillis - nowEpochMillis > MAX_TTL_MILLIS) {
      return PairingResult.Failure("Pairing QR TTL exceeds maximum allowed window (15m)")
    }

    val endpoints = params["ep"]?.split(',')?.filter { it.isNotEmpty() }.orEmpty()
    if (endpoints.size > 6 || endpoints.any { !ENDPOINT_HINT_REGEX.matches(it) }) {
      return PairingResult.Failure("Invalid endpoint hint format")
    }

    return PairingResult.Success(
      PairingPayload(
        version = version,
        nodeId = nodeId,
        publicKey = publicKey,
        endpointHints = endpoints,
        singleUseToken = tokRaw,
        expiresAtEpochMillis = expMillis,
      )
    )
  }

  fun formatUri(payload: PairingPayload): String {
    val epPart = if (payload.endpointHints.isEmpty()) "" else "&ep=${payload.endpointHints.joinToString(",")}"
    return "homenode://pair?v=${payload.version}&node=${payload.nodeId}&pub=${payload.publicKey.base64Url}${epPart}&tok=${payload.singleUseToken}&exp=${payload.expiresAtEpochMillis}"
  }

  const val MAX_TTL_MILLIS: Long = 15L * 60L * 1000L
}

/**
 * Mode A Pairing Coordinator (§5, Slice S17):
 * - Generates short-lived single-use 128-bit introduction tokens.
 * - Consumes token on first use; invalidates after [MAX_FAILED_ATTEMPTS] failures.
 * - Requires explicit node-user confirmation of peer label and per-mount capabilities.
 */
class ModeAPairingCoordinator(
  private val authorizer: PeerAuthorizer,
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
) {
  private val rng = SecureRandom()
  private val activeTokens = ConcurrentHashMap<String, IssuedToken>()
  private var failureCount = 0

  private data class IssuedToken(
    val token: String,
    val expiresAtEpochMillis: Long,
  )

  fun createNodeIntroductionQr(
    nodeIdentity: NodePublicIdentity,
    endpointHints: List<String>,
    ttlMillis: Long = 5L * 60L * 1000L,
  ): PairingPayload {
    val tokenBytes = ByteArray(16).also { rng.nextBytes(it) }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)
    val exp = clockEpochMillis() + ttlMillis.coerceIn(30_000L, PairingPayloadParser.MAX_TTL_MILLIS)
    activeTokens[token] = IssuedToken(token, exp)
    return PairingPayload(
      version = PairingPayloadParser.SUPPORTED_VERSION,
      nodeId = nodeIdentity.nodeId,
      publicKey = nodeIdentity.publicKey,
      endpointHints = endpointHints.take(4),
      singleUseToken = token,
      expiresAtEpochMillis = exp,
    )
  }

  @Synchronized
  fun confirmPeerFromScannedQr(
    scannedPeerQrUri: String,
    userConfirmedLabel: String,
    userSelectedCapabilities: Set<Capability>,
    peerExpiryEpochMillis: Long? = null,
  ): PairingResult<PeerRecord> {
    val now = clockEpochMillis()
    val parsed = PairingPayloadParser.parse(scannedPeerQrUri, now)
    if (parsed is PairingResult.Failure) {
      recordFailure()
      return parsed
    }
    val payload = (parsed as PairingResult.Success).value
    val issued = activeTokens.remove(payload.singleUseToken)
    if (issued == null || issued.expiresAtEpochMillis <= now) {
      recordFailure()
      return PairingResult.Failure("Pairing token unknown, already consumed, or expired")
    }
    failureCount = 0
    val record = authorizer.registerOrUpdatePeer(
      peerId = payload.publicKey,
      label = userConfirmedLabel,
      capabilities = userSelectedCapabilities,
      expiresAtEpochMillis = peerExpiryEpochMillis,
    )
    return PairingResult.Success(record)
  }

  private fun recordFailure() {
    failureCount++
    if (failureCount >= MAX_FAILED_ATTEMPTS) {
      activeTokens.clear()
      failureCount = 0
    }
  }

  companion object {
    const val MAX_FAILED_ATTEMPTS = 3
  }
}
