package com.homenode.service.files

import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.identity.PeerId
import com.homenode.core.storage.AccessMode
import com.homenode.core.storage.Capability
import com.homenode.core.storage.FileBackend
import com.homenode.core.storage.FileEntry
import com.homenode.core.storage.MountId
import com.homenode.core.storage.MountState
import com.homenode.core.storage.PathValidator
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageException
import com.homenode.core.storage.StorageMount
import com.homenode.core.storage.StorageResult
import com.homenode.core.transport.Transport
import com.homenode.core.transport.TransportResult
import com.homenode.core.transport.TransportStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Resolves mounted backends for [FileService] without exposing provider libraries to `:service-files` (§3, §8).
 */
interface MountCatalog {
  fun listMounts(): List<StorageMount>
  fun getMount(mountId: MountId): StorageMount?
  fun getBackend(mountId: MountId): FileBackend?
}

/**
 * FileService on tunnel port 7001 (§9, Slice S5).
 * Enforces the full per-request security pipeline:
 * `receive -> bound-check -> decode -> derive peer from transport -> parse path -> split mount segment ->`
 * `validate SafePath -> authorize Files(mount, READ|WRITE) -> check mount state & readOnly -> execute -> respond`.
 */
class FileService(
  private val transport: Transport,
  private val authorizer: PeerAuthorizer,
  private val mountCatalog: MountCatalog,
  private val onRequestDeniedAudit: () -> Unit = {},
  private val perRequestTimeoutMs: Long = 30_000L,
) {
  private var acceptJob: Job? = null

  fun start(scope: CoroutineScope) {
    if (acceptJob?.isActive == true) return
    val incomingStreams = transport.listen(FILE_SERVICE_PORT)
    acceptJob = scope.launch {
      incomingStreams.collect { stream ->
        launch {
          handlePeerStream(stream)
        }
      }
    }
  }

  fun stop() {
    acceptJob?.cancel()
    acceptJob = null
  }

  internal suspend fun handlePeerStream(stream: TransportStream) {
    // Cryptographic peer identity derived strictly from transport cryptokey routing (§5, §9)
    val peerId = PeerId.parse(stream.remotePeer.base64Url) ?: run {
      stream.close()
      return
    }

    var negotiatedMaxFrame = FrameCodec.MAX_FRAME_BYTES
    var helloCompleted = false
    var violations = 0

    try {
      while (!stream.isClosed) {
        val rawRes = stream.readFrameBytes(negotiatedMaxFrame + FrameCodec.HEADER_BYTES)
        if (rawRes is TransportResult.Failure) {
          sendError(stream, 0, "FRAME_TOO_LARGE", "Frame exceeded limit")
          stream.close()
          return
        }
        val rawBytes = (rawRes as TransportResult.Success).value ?: break
        val decoded = FrameCodec.decodeFrame(rawBytes, negotiatedMaxFrame)
        if (decoded is CodecResult.Malformed) {
          violations++
          sendError(stream, 0, decoded.code, decoded.message)
          if (violations >= MAX_VIOLATIONS_PER_STREAM) {
            stream.close()
            return
          }
          continue
        }

        val frame = (decoded as CodecResult.Success).value
        if (!helloCompleted) {
          if (frame.type != FrameType.HELLO) {
            sendError(stream, frame.requestId, "BAD_REQUEST", "First frame must be HELLO")
            stream.close()
            return
          }
          val helloRes = ProtocolV2PayloadCodec.decodeHello(frame.payload)
          if (helloRes is CodecResult.Malformed) {
            sendError(stream, frame.requestId, "BAD_REQUEST", helloRes.message)
            stream.close()
            return
          }
          val hello = (helloRes as CodecResult.Success).value
          if (hello.version != FrameCodec.PROTOCOL_VERSION_V2) {
            sendError(stream, frame.requestId, "UNSUPPORTED_VERSION", "Only protocol v2 is supported")
            stream.close()
            return
          }
          negotiatedMaxFrame = hello.maxFrameBytes.coerceIn(4096, FrameCodec.MAX_FRAME_BYTES)
          val reply = ProtocolV2PayloadCodec.encodeHello(
            ProtocolMessage.Hello(FrameCodec.PROTOCOL_VERSION_V2, negotiatedMaxFrame)
          )
          stream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.HELLO, 0, frame.requestId, reply)))
          helloCompleted = true
          continue
        }

        val timedResult = withTimeoutOrNull(perRequestTimeoutMs) {
          dispatchAuthenticatedFrame(stream, peerId, frame, negotiatedMaxFrame)
        }
        if (timedResult == null) {
          sendError(stream, frame.requestId, StorageError.TIMEOUT.name, "Request deadline exceeded")
        } else if (!timedResult) {
          violations++
          if (violations >= MAX_VIOLATIONS_PER_STREAM) {
            stream.close()
            return
          }
        }
      }
    } finally {
      stream.close()
    }
  }

  /**
   * Returns `true` if frame was well-formed, `false` if malformed (counting toward stream violation limit).
   */
  private suspend fun dispatchAuthenticatedFrame(
    stream: TransportStream,
    peerId: PeerId,
    frame: WireFrame,
    negotiatedMaxFrame: Int,
  ): Boolean {
    return when (frame.type) {
      FrameType.LIST -> {
        val req = (ProtocolV2PayloadCodec.decodeListReq(frame.payload) as? CodecResult.Success)?.value
          ?: run {
            sendError(stream, frame.requestId, "BAD_REQUEST", "Malformed LIST")
            return false
          }
        handleList(stream, peerId, frame.requestId, req)
        true
      }
      FrameType.STAT -> {
        val req = (ProtocolV2PayloadCodec.decodeStatReq(frame.payload) as? CodecResult.Success)?.value
          ?: run {
            sendError(stream, frame.requestId, "BAD_REQUEST", "Malformed STAT")
            return false
          }
        handleStat(stream, peerId, frame.requestId, req)
        true
      }
      FrameType.READ -> {
        val req = (ProtocolV2PayloadCodec.decodeReadReq(frame.payload) as? CodecResult.Success)?.value
          ?: run {
            sendError(stream, frame.requestId, "BAD_REQUEST", "Malformed READ")
            return false
          }
        handleRead(stream, peerId, frame.requestId, req, negotiatedMaxFrame)
        true
      }
      FrameType.WRITE -> {
        val req = (ProtocolV2PayloadCodec.decodeWriteReq(frame.payload) as? CodecResult.Success)?.value
          ?: run {
            sendError(stream, frame.requestId, "BAD_REQUEST", "Malformed WRITE")
            return false
          }
        handleWrite(stream, peerId, frame.requestId, req, negotiatedMaxFrame)
        true
      }
      FrameType.MKDIR -> {
        val req = (ProtocolV2PayloadCodec.decodeMkdirReq(frame.payload) as? CodecResult.Success)?.value
          ?: run {
            sendError(stream, frame.requestId, "BAD_REQUEST", "Malformed MKDIR")
            return false
          }
        handleMkdir(stream, peerId, frame.requestId, req)
        true
      }
      FrameType.DELETE -> {
        val req = (ProtocolV2PayloadCodec.decodeDeleteReq(frame.payload) as? CodecResult.Success)?.value
          ?: run {
            sendError(stream, frame.requestId, "BAD_REQUEST", "Malformed DELETE")
            return false
          }
        handleDelete(stream, peerId, frame.requestId, req)
        true
      }
      FrameType.MOVE -> {
        val req = (ProtocolV2PayloadCodec.decodeMoveReq(frame.payload) as? CodecResult.Success)?.value
          ?: run {
            sendError(stream, frame.requestId, "BAD_REQUEST", "Malformed MOVE")
            return false
          }
        handleMove(stream, peerId, frame.requestId, req)
        true
      }
      FrameType.CANCEL -> {
        sendOk(stream, frame.requestId, ProtocolV2PayloadCodec.encodeOkUnit())
        true
      }
      else -> {
        sendError(stream, frame.requestId, "BAD_REQUEST", "Unexpected frame type ${frame.type}")
        false
      }
    }
  }

  private suspend fun handleList(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    req: ProtocolMessage.ListReq,
  ) {
    val vpRes = PathValidator.parseVirtualPath(req.virtualPath)
    if (vpRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, vpRes)
      return
    }
    val vp = (vpRes as StorageResult.Success).value
    val mountId = vp.mountId
    // Root `/` lists only mounts for which the peer holds at least READ (§8.2)
    if (mountId == null) {
      val visible = authorizer.visibleMountsForPeer(peerId, mountCatalog.listMounts())
      val entries = visible.map { mount ->
        FileEntry(
          name = mount.id.value,
          isDirectory = true,
          sizeBytes = 0L,
          lastModifiedEpochMillis = 0L,
        )
      }
      sendOk(stream, requestId, ProtocolV2PayloadCodec.encodeOkList(entries, null))
      return
    }

    val backend = authorizeAndResolveBackend(stream, peerId, requestId, mountId, AccessMode.READ) ?: return
    when (val res = backend.list(vp.relativePath, req.pageSize, req.pageToken)) {
      is StorageResult.Success -> sendOk(
        stream,
        requestId,
        ProtocolV2PayloadCodec.encodeOkList(res.value.entries, res.value.nextPageToken)
      )
      is StorageResult.Failure -> sendStorageFailure(stream, requestId, res)
    }
  }

  private suspend fun handleStat(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    req: ProtocolMessage.StatReq,
  ) {
    val vpRes = PathValidator.parseVirtualPath(req.virtualPath)
    if (vpRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, vpRes)
      return
    }
    val vp = (vpRes as StorageResult.Success).value
    val mountId = vp.mountId ?: run {
      sendError(stream, requestId, StorageError.PATH_INVALID.name, "Mount ID required for STAT")
      return
    }
    val backend = authorizeAndResolveBackend(stream, peerId, requestId, mountId, AccessMode.READ) ?: return
    when (val res = backend.stat(vp.relativePath)) {
      is StorageResult.Success -> sendOk(stream, requestId, ProtocolV2PayloadCodec.encodeOkStat(res.value))
      is StorageResult.Failure -> sendStorageFailure(stream, requestId, res)
    }
  }

  private suspend fun handleRead(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    req: ProtocolMessage.ReadReq,
    negotiatedMaxFrame: Int,
  ) {
    val vpRes = PathValidator.parseVirtualPath(req.virtualPath)
    if (vpRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, vpRes)
      return
    }
    val vp = (vpRes as StorageResult.Success).value
    val mountId = vp.mountId ?: run {
      sendError(stream, requestId, StorageError.PATH_INVALID.name, "Mount ID required for READ")
      return
    }
    val backend = authorizeAndResolveBackend(stream, peerId, requestId, mountId, AccessMode.READ) ?: return
    try {
      backend.open(vp.relativePath, req.offset, req.length).collect { chunk ->
        val frame = WireFrame(FrameType.DATA, 0, requestId, chunk)
        stream.writeFrameBytes(FrameCodec.encodeFrame(frame, negotiatedMaxFrame))
      }
      val endFrame = WireFrame(FrameType.END, 0, requestId, ByteArray(0))
      stream.writeFrameBytes(FrameCodec.encodeFrame(endFrame, negotiatedMaxFrame))
    } catch (se: StorageException) {
      sendError(stream, requestId, se.error.name, se.message)
    }
  }

  private suspend fun handleWrite(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    req: ProtocolMessage.WriteReq,
    negotiatedMaxFrame: Int,
  ) {
    val vpRes = PathValidator.parseVirtualPath(req.virtualPath)
    if (vpRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, vpRes)
      return
    }
    val vp = (vpRes as StorageResult.Success).value
    val mountId = vp.mountId ?: run {
      sendError(stream, requestId, StorageError.PATH_INVALID.name, "Mount ID required for WRITE")
      return
    }
    val backend = authorizeAndResolveBackend(stream, peerId, requestId, mountId, AccessMode.WRITE) ?: return

    val dataFlow = flow {
      while (true) {
        val nextRaw = stream.readFrameBytes(negotiatedMaxFrame + FrameCodec.HEADER_BYTES).getOrThrow()
          ?: throw StorageException(StorageError.CANCELLED, "Stream closed mid-write")
        val nextFrame = (FrameCodec.decodeFrame(nextRaw, negotiatedMaxFrame) as? CodecResult.Success)?.value
          ?: throw StorageException(StorageError.PATH_INVALID, "Malformed DATA/END frame during write")
        when (nextFrame.type) {
          FrameType.DATA -> emit(nextFrame.payload)
          FrameType.END -> break
          FrameType.CANCEL -> throw StorageException(StorageError.CANCELLED, "Write cancelled by peer")
          else -> throw StorageException(StorageError.PATH_INVALID, "Expected DATA or END frame")
        }
      }
    }

    when (val res = backend.write(vp.relativePath, req.mode, dataFlow, req.expectedSize)) {
      is StorageResult.Success -> sendOk(stream, requestId, ProtocolV2PayloadCodec.encodeOkStat(res.value))
      is StorageResult.Failure -> sendStorageFailure(stream, requestId, res)
    }
  }

  private suspend fun handleMkdir(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    req: ProtocolMessage.MkdirReq,
  ) {
    val vpRes = PathValidator.parseVirtualPath(req.virtualPath)
    if (vpRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, vpRes)
      return
    }
    val vp = (vpRes as StorageResult.Success).value
    val mountId = vp.mountId ?: run {
      sendError(stream, requestId, StorageError.PATH_INVALID.name, "Mount ID required")
      return
    }
    val backend = authorizeAndResolveBackend(stream, peerId, requestId, mountId, AccessMode.WRITE) ?: return
    when (val res = backend.mkdir(vp.relativePath)) {
      is StorageResult.Success -> sendOk(stream, requestId, ProtocolV2PayloadCodec.encodeOkStat(res.value))
      is StorageResult.Failure -> sendStorageFailure(stream, requestId, res)
    }
  }

  private suspend fun handleDelete(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    req: ProtocolMessage.DeleteReq,
  ) {
    val vpRes = PathValidator.parseVirtualPath(req.virtualPath)
    if (vpRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, vpRes)
      return
    }
    val vp = (vpRes as StorageResult.Success).value
    val mountId = vp.mountId ?: run {
      sendError(stream, requestId, StorageError.DENIED.name, "Cannot delete root")
      return
    }
    val backend = authorizeAndResolveBackend(stream, peerId, requestId, mountId, AccessMode.WRITE) ?: return
    when (val res = backend.delete(vp.relativePath, req.recursive)) {
      is StorageResult.Success -> sendOk(stream, requestId, ProtocolV2PayloadCodec.encodeOkUnit())
      is StorageResult.Failure -> sendStorageFailure(stream, requestId, res)
    }
  }

  private suspend fun handleMove(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    req: ProtocolMessage.MoveReq,
  ) {
    val srcRes = PathValidator.parseVirtualPath(req.srcVirtualPath)
    val dstRes = PathValidator.parseVirtualPath(req.dstVirtualPath)
    if (srcRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, srcRes)
      return
    }
    if (dstRes is StorageResult.Failure) {
      sendStorageFailure(stream, requestId, dstRes)
      return
    }
    val srcVp = (srcRes as StorageResult.Success).value
    val dstVp = (dstRes as StorageResult.Success).value
    val srcMountId = srcVp.mountId
    val dstMountId = dstVp.mountId
    if (srcMountId == null || dstMountId == null) {
      sendError(stream, requestId, StorageError.PATH_INVALID.name, "Mount ID required for MOVE")
      return
    }
    // Cross-mount MOVE is rejected in v1 with UNSUPPORTED (§8.2)
    if (srcMountId != dstMountId) {
      sendError(stream, requestId, StorageError.UNSUPPORTED.name, "Cross-mount MOVE is unsupported in v1")
      return
    }
    val backend = authorizeAndResolveBackend(stream, peerId, requestId, srcMountId, AccessMode.WRITE) ?: return
    when (val res = backend.move(srcVp.relativePath, dstVp.relativePath)) {
      is StorageResult.Success -> sendOk(stream, requestId, ProtocolV2PayloadCodec.encodeOkStat(res.value))
      is StorageResult.Failure -> sendStorageFailure(stream, requestId, res)
    }
  }

  private suspend fun authorizeAndResolveBackend(
    stream: TransportStream,
    peerId: PeerId,
    requestId: Int,
    mountId: MountId,
    requiredMode: AccessMode,
  ): FileBackend? {
    if (!authorizer.can(peerId, Capability.Files(mountId, requiredMode))) {
      onRequestDeniedAudit()
      sendError(stream, requestId, StorageError.DENIED.name, "Capability Files($mountId, $requiredMode) denied")
      return null
    }
    val mount = mountCatalog.getMount(mountId)
    if (mount == null || mount.state is MountState.Removed) {
      sendError(stream, requestId, StorageError.NOT_FOUND.name, "Mount not found")
      return null
    }
    when (mount.state) {
      is MountState.NeedsReauth -> {
        sendError(stream, requestId, StorageError.AUTH_REQUIRED.name, "Mount requires node re-authentication")
        return null
      }
      is MountState.Unavailable -> {
        sendError(stream, requestId, StorageError.UNAVAILABLE.name, "Mount currently unavailable")
        return null
      }
      else -> Unit
    }
    if (requiredMode == AccessMode.WRITE && mount.readOnly) {
      onRequestDeniedAudit()
      sendError(stream, requestId, StorageError.DENIED.name, "Mount is configured read-only on node")
      return null
    }
    val backend = mountCatalog.getBackend(mountId)
    if (backend == null) {
      sendError(stream, requestId, StorageError.UNAVAILABLE.name, "Mount backend not ready")
      return null
    }
    return backend
  }

  private suspend fun sendOk(stream: TransportStream, requestId: Int, payload: ByteArray) {
    stream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.OK, 0, requestId, payload)))
  }

  private suspend fun sendStorageFailure(
    stream: TransportStream,
    requestId: Int,
    failure: StorageResult.Failure,
  ) {
    if (failure.error == StorageError.DENIED) {
      onRequestDeniedAudit()
    }
    sendError(stream, requestId, failure.error.name, failure.message)
  }

  private suspend fun sendError(
    stream: TransportStream,
    requestId: Int,
    code: String,
    message: String,
  ) {
    val payload = ProtocolV2PayloadCodec.encodeError(code, message)
    stream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.ERROR, 0, requestId, payload)))
  }

  companion object {
    const val FILE_SERVICE_PORT = 7001
    const val MAX_VIOLATIONS_PER_STREAM = 3
  }
}
