package com.homenode.service.files

import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.identity.PeerId
import com.homenode.core.storage.AccessMode
import com.homenode.core.storage.Capability
import com.homenode.core.storage.FileBackend
import com.homenode.core.storage.InMemoryFileBackend
import com.homenode.core.storage.MountConfig
import com.homenode.core.storage.MountId
import com.homenode.core.storage.MountKind
import com.homenode.core.storage.MountState
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageMount
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.WriteMode
import com.homenode.core.transport.PeerEndpointConfig
import com.homenode.core.transport.PeerPublicKey
import com.homenode.core.transport.TestTransport
import com.homenode.core.transport.TestTransportHub
import com.homenode.core.transport.TransportStream
import com.homenode.core.transport.TunnelIp
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FileServiceIntegrationTest {

  private suspend fun negotiateHello(stream: TransportStream) {
    val helloPayload = ProtocolV2PayloadCodec.encodeHello(
      ProtocolMessage.Hello(FrameCodec.PROTOCOL_VERSION_V2, FrameCodec.MAX_FRAME_BYTES)
    )
    stream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.HELLO, 0, 1, helloPayload)))
    val replyRaw = stream.readFrameBytes(FrameCodec.MAX_FRAME_BYTES + FrameCodec.HEADER_BYTES).getOrThrow()!!
    val replyFrame = (FrameCodec.decodeFrame(replyRaw) as CodecResult.Success).value
    assertEquals(FrameType.HELLO, replyFrame.type)
  }

  @Test
  fun twoRuntimeFileService_routesByMountIdEnforcesCapabilitiesAndRejectsCrossMountMove() = runTest {
    val hub = TestTransportHub()
    val nodePubBytes = ByteArray(32) { (it + 1).toByte() }
    val peerPubBytes = ByteArray(32) { (it + 50).toByte() }
    val nodeKey = PeerPublicKey.fromBytes(nodePubBytes).getOrThrow()
    val peerKey = PeerPublicKey.fromBytes(peerPubBytes).getOrThrow()
    val peerId = PeerId.fromBytes(peerPubBytes)

    val nodeIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val peerIp = TunnelIp.parse("10.66.0.2").getOrThrow()

    val nodeTransport = TestTransport(nodeKey, nodeIp, hub)
    val peerTransport = TestTransport(peerKey, peerIp, hub)
    nodeTransport.start()
    peerTransport.start()
    nodeTransport.addPeer(PeerEndpointConfig(peerKey, peerIp))
    peerTransport.addPeer(PeerEndpointConfig(nodeKey, nodeIp))

    val mountLocalA = StorageMount(
      id = MountId.generate(),
      kind = MountKind.LOCAL,
      provider = StorageProvider.SAF,
      label = "Internal Shared",
      config = MountConfig.SafConfig("content://tree/a"),
      credentialRef = null,
      readOnly = false,
      state = MountState.Ready,
    )
    val mountCloudSecret = StorageMount(
      id = MountId.generate(),
      kind = MountKind.CLOUD,
      provider = StorageProvider.GOOGLE_DRIVE,
      label = "Private Drive",
      config = MountConfig.CloudConfig(StorageProvider.GOOGLE_DRIVE, "me@example.com", "root"),
      credentialRef = null,
      readOnly = false,
      state = MountState.Ready,
    )

    val backendA = InMemoryFileBackend(isReadOnly = false)
    val backendCloud = InMemoryFileBackend(isReadOnly = false)

    val catalog = object : MountCatalog {
      override fun listMounts(): List<StorageMount> = listOf(mountLocalA, mountCloudSecret)
      override fun getMount(mountId: MountId): StorageMount? =
        listMounts().firstOrNull { it.id == mountId }
      override fun getBackend(mountId: MountId): FileBackend? = when (mountId) {
        mountLocalA.id -> backendA
        mountCloudSecret.id -> backendCloud
        else -> null
      }
    }

    val authorizer = PeerAuthorizer()
    // Grant peer WRITE on mountLocalA ONLY; mountCloudSecret has NO grant
    authorizer.registerOrUpdatePeer(
      peerId = peerId,
      label = "Peer Laptop",
      capabilities = setOf(Capability.Files(mountLocalA.id, AccessMode.WRITE)),
    )

    val deniedAuditCount = AtomicInteger(0)
    val service = FileService(
      transport = nodeTransport,
      authorizer = authorizer,
      mountCatalog = catalog,
      onRequestDeniedAudit = { deniedAuditCount.incrementAndGet() },
    )
    service.start(backgroundScope)

    val clientStream = peerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    negotiateHello(clientStream)

    // 1. Root `/` LIST returns ONLY mountLocalA (mountCloudSecret is hidden because peer lacks READ)
    val listRootReq = ProtocolV2PayloadCodec.encodeListReq(ProtocolMessage.ListReq("/"))
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.LIST, 0, 2, listRootReq)))
    val listRootFrame = (FrameCodec.decodeFrame(clientStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, listRootFrame.type)
    val rootEntries = (ProtocolV2PayloadCodec.decodeOkPayload(listRootFrame.payload) as CodecResult.Success).value as ProtocolMessage.OkListResp
    assertEquals(listOf(mountLocalA.id.value), rootEntries.entries.map { it.name })

    // 2. WRITE + READ 90 KiB file on mountLocalA
    val fileBytes = ByteArray(90 * 1024) { (it % 199).toByte() }
    val vPath = "/${mountLocalA.id.value}/notes.bin"
    val writeReq = ProtocolV2PayloadCodec.encodeWriteReq(
      ProtocolMessage.WriteReq(vPath, WriteMode.CREATE_NEW, fileBytes.size.toLong())
    )
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.WRITE, 0, 3, writeReq)))
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 3, fileBytes.copyOfRange(0, 64 * 1024))))
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 3, fileBytes.copyOfRange(64 * 1024, fileBytes.size))))
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.END, 0, 3, ByteArray(0))))

    val writeRespFrame = (FrameCodec.decodeFrame(clientStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, writeRespFrame.type)

    // Read back via READ
    val readReq = ProtocolV2PayloadCodec.encodeReadReq(ProtocolMessage.ReadReq(vPath))
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.READ, 0, 4, readReq)))
    val receivedOut = ByteArrayOutputStream()
    while (true) {
      val f = (FrameCodec.decodeFrame(clientStream.readFrameBytes(128 * 1024).getOrThrow()!!) as CodecResult.Success).value
      if (f.type == FrameType.DATA) {
        receivedOut.write(f.payload)
      } else if (f.type == FrameType.END) {
        break
      }
    }
    assertArrayEquals(fileBytes, receivedOut.toByteArray())

    // 3. Unauthorized access to mountCloudSecret must be DENIED and increment audit counter
    val unauthorizedStat = ProtocolV2PayloadCodec.encodeStatReq(
      ProtocolMessage.StatReq("/${mountCloudSecret.id.value}/secret.txt")
    )
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.STAT, 0, 5, unauthorizedStat)))
    val errFrame = (FrameCodec.decodeFrame(clientStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.ERROR, errFrame.type)
    val decodedErr = (ProtocolV2PayloadCodec.decodeError(errFrame.payload) as CodecResult.Success).value
    assertEquals(StorageError.DENIED.name, decodedErr.errorCode)
    assertEquals(1, deniedAuditCount.get())

    // 4. Cross-mount MOVE is rejected with UNSUPPORTED (§8.2)
    val crossMove = ProtocolV2PayloadCodec.encodeMoveReq(
      ProtocolMessage.MoveReq(
        srcVirtualPath = vPath,
        dstVirtualPath = "/${mountCloudSecret.id.value}/notes.bin",
      )
    )
    clientStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.MOVE, 0, 6, crossMove)))
    val moveErrFrame = (FrameCodec.decodeFrame(clientStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    val moveErr = (ProtocolV2PayloadCodec.decodeError(moveErrFrame.payload) as CodecResult.Success).value
    assertEquals(StorageError.UNSUPPORTED.name, moveErr.errorCode)

    clientStream.close()
    service.stop()
  }

  @Test
  fun frameCodec_rejectsOversizedHeaderBeforeAllocationAndMalformedStreamsAfterThreeStrikes() {
    val oversizedHeader = ByteBuffer.allocate(FrameCodec.HEADER_BYTES)
      .putInt(FrameCodec.MAX_FRAME_BYTES + 1)
      .put(FrameType.STAT.code)
      .put(0.toByte())
      .putInt(99)
      .array()
    val res = FrameCodec.decodeFrame(oversizedHeader)
    assertTrue(res is CodecResult.Malformed)
    assertEquals("FRAME_TOO_LARGE", (res as CodecResult.Malformed).code)
  }
}
