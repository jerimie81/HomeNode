package com.homenode.core.transport

import java.util.Base64
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/**
 * 32-byte Curve25519 (X25519) static public key identifying a peer (§4, §6).
 */
class PeerPublicKey private constructor(private val bytes: ByteArray) {
  val base64Url: String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

  val shortFingerprint: String
    get() = base64Url.take(8)

  fun toByteArray(): ByteArray = bytes.copyOf()

  override fun equals(other: Any?): Boolean =
    other is PeerPublicKey && bytes.contentEquals(other.bytes)

  override fun hashCode(): Int = bytes.contentHashCode()

  override fun toString(): String = "PeerPublicKey(${shortFingerprint}…)"

  companion object {
    const val KEY_LEN_BYTES = 32

    fun fromBytes(raw: ByteArray): TransportResult<PeerPublicKey> {
      if (raw.size != KEY_LEN_BYTES) {
        return TransportResult.Failure(
          TransportError.InvalidConfig("X25519 public key must be $KEY_LEN_BYTES bytes, got ${raw.size}")
        )
      }
      if (raw.all { it == 0.toByte() }) {
        return TransportResult.Failure(
          TransportError.InvalidConfig("All-zero X25519 public key is forbidden")
        )
      }
      return TransportResult.Success(PeerPublicKey(raw.copyOf()))
    }

    fun fromBase64Url(encoded: String): TransportResult<PeerPublicKey> {
      return try {
        val decoded = Base64.getUrlDecoder().decode(encoded)
        fromBytes(decoded)
      } catch (e: IllegalArgumentException) {
        TransportResult.Failure(TransportError.InvalidConfig("Invalid base64url public key"))
      }
    }
  }
}

/**
 * Unique `/32` IPv4 address in the private HomeNode tunnel subnet (`10.66.0.0/16`) (§6).
 */
@JvmInline
value class TunnelIp private constructor(val address: String) {
  val cidr32: String get() = "$address/32"

  override fun toString(): String = address

  companion object {
    private val TUNNEL_IPV4_REGEX =
      Regex("""^10\.66\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$""")

    fun parse(rawIpOrCidr: String): TransportResult<TunnelIp> {
      val trimmed = rawIpOrCidr.trim()
      if (trimmed == "0.0.0.0/0" || trimmed == "::/0" || trimmed.endsWith("/0")) {
        return TransportResult.Failure(
          TransportError.InvalidConfig("Wildcard AllowedIPs (0.0.0.0/0) is strictly forbidden (§6)")
        )
      }
      val ipPart = if (trimmed.endsWith("/32")) {
        trimmed.removeSuffix("/32")
      } else if (trimmed.contains('/')) {
        return TransportResult.Failure(
          TransportError.InvalidConfig("Only /32 peer AllowedIPs are permitted, got: $trimmed")
        )
      } else {
        trimmed
      }
      if (!TUNNEL_IPV4_REGEX.matches(ipPart)) {
        return TransportResult.Failure(
          TransportError.InvalidConfig("Tunnel IP must be inside 10.66.0.0/16 host range: $ipPart")
        )
      }
      return TransportResult.Success(TunnelIp(ipPart))
    }
  }
}

data class PeerEndpointConfig(
  val peerPublicKey: PeerPublicKey,
  val allowedTunnelIp: TunnelIp,
  val endpointHint: String? = null,
)

enum class TransportState {
  STOPPED,
  STARTING,
  RUNNING,
  DEGRADED,
  FAILED,
}

/**
 * Explicitly distinguishes whether a [Transport] is backed by a real tunnel engine,
 * an in-process simulation ([TestTransport]), or an unimplemented/stubbed native engine.
 */
enum class TransportImplementationStatus {
  REAL,
  SIMULATED,
  UNAVAILABLE,
}

/**
 * Explicit dependency-injection selector so test/simulation transport and production WireGuard
 * transport cannot be accidentally confused.
 */
enum class TransportSelectionMode {
  TEST_IN_PROCESS,
  PRODUCTION_WIREGUARD,
}

sealed interface TransportError {
  val message: String

  data class InvalidConfig(override val message: String) : TransportError
  data class PeerNotAuthorized(override val message: String) : TransportError
  data class CryptokeyRoutingMismatch(override val message: String) : TransportError
  data class ConnectionRefused(override val message: String) : TransportError
  data class Timeout(override val message: String) : TransportError
  data class Closed(override val message: String) : TransportError
  data class EngineUnavailable(override val message: String) : TransportError
}

class TransportException(val error: TransportError) : Exception(error.message)

sealed interface TransportResult<out T> {
  data class Success<T>(val value: T) : TransportResult<T>
  data class Failure(val error: TransportError) : TransportResult<Nothing>

  val isSuccess: Boolean get() = this is Success
  val isFailure: Boolean get() = this is Failure

  fun getOrThrow(): T = when (this) {
    is Success -> value
    is Failure -> throw TransportException(error)
  }
}

inline fun <T> TransportResult<T>.getOrElse(onFailure: (TransportError) -> T): T =
  when (this) {
    is TransportResult.Success -> value
    is TransportResult.Failure -> onFailure(this.error)
  }

/**
 * Bidirectional stream inside the encrypted peer-to-peer tunnel.
 * [remotePeer] is guaranteed by cryptokey routing (`source tunnel IP ↔ PeerPublicKey`), never from payload bytes (§6).
 */
interface TransportStream {
  val remotePeer: PeerPublicKey
  val remoteTunnelIp: TunnelIp
  val port: Int
  val isClosed: Boolean

  suspend fun readFrameBytes(maxBytes: Int): TransportResult<ByteArray?>
  suspend fun writeFrameBytes(bytes: ByteArray): TransportResult<Unit>
  suspend fun close()
}

/**
 * Transport contract (§3, §6). No WireGuard types appear in this interface.
 */
interface Transport {
  val state: StateFlow<TransportState>
  val implementationStatus: TransportImplementationStatus
    get() = TransportImplementationStatus.REAL
  val localPublicKey: PeerPublicKey
  val localTunnelIp: TunnelIp

  suspend fun start(): TransportResult<Unit>
  suspend fun stop(): TransportResult<Unit>
  suspend fun addPeer(config: PeerEndpointConfig): TransportResult<Unit>
  suspend fun removePeer(peerPublicKey: PeerPublicKey): TransportResult<Unit>
  suspend fun openStream(targetPeer: PeerPublicKey, port: Int): TransportResult<TransportStream>
  fun listen(port: Int): Flow<TransportStream>
}
