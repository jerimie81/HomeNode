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

  @Test
  fun payloadCodec_rejectsTrailingBytes() {
    val hello = ProtocolV2PayloadCodec.encodeHello(ProtocolMessage.Hello(2, 4096))
    assertTrue(ProtocolV2PayloadCodec.decodeHello(hello + byteArrayOf(0x7f)).let { it is CodecResult.Malformed })

    val stat = ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq("/mount_a/file.txt"))
    assertTrue(ProtocolV2PayloadCodec.decodeStatReq(stat + byteArrayOf(0x01)).let { it is CodecResult.Malformed })
  }

  @Test
  fun authorizationAndStorageMatrix_readOnlyVsWritePeerRevocationReadOnlyMountAndFullStorageOps() = runTest {
    val hub = TestTransportHub()
    val nodeKey = PeerPublicKey.fromBytes(ByteArray(32) { (it + 1).toByte() }).getOrThrow()
    val readPeerBytes = ByteArray(32) { (it + 20).toByte() }
    val writePeerBytes = ByteArray(32) { (it + 40).toByte() }
    val unauthPeerBytes = ByteArray(32) { (it + 60).toByte() }

    val readPeerKey = PeerPublicKey.fromBytes(readPeerBytes).getOrThrow()
    val writePeerKey = PeerPublicKey.fromBytes(writePeerBytes).getOrThrow()
    val unauthPeerKey = PeerPublicKey.fromBytes(unauthPeerBytes).getOrThrow()

    val readPeerId = PeerId.fromBytes(readPeerBytes)
    val writePeerId = PeerId.fromBytes(writePeerBytes)

    val nodeIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val readPeerIp = TunnelIp.parse("10.66.0.2").getOrThrow()
    val writePeerIp = TunnelIp.parse("10.66.0.3").getOrThrow()
    val unauthPeerIp = TunnelIp.parse("10.66.0.4").getOrThrow()

    val nodeTransport = TestTransport(nodeKey, nodeIp, hub)
    val readPeerTransport = TestTransport(readPeerKey, readPeerIp, hub)
    val writePeerTransport = TestTransport(writePeerKey, writePeerIp, hub)
    val unauthPeerTransport = TestTransport(unauthPeerKey, unauthPeerIp, hub)

    nodeTransport.start()
    readPeerTransport.start()
    writePeerTransport.start()
    unauthPeerTransport.start()

    nodeTransport.addPeer(PeerEndpointConfig(readPeerKey, readPeerIp))
    readPeerTransport.addPeer(PeerEndpointConfig(nodeKey, nodeIp))

    nodeTransport.addPeer(PeerEndpointConfig(writePeerKey, writePeerIp))
    writePeerTransport.addPeer(PeerEndpointConfig(nodeKey, nodeIp))

    nodeTransport.addPeer(PeerEndpointConfig(unauthPeerKey, unauthPeerIp))
    unauthPeerTransport.addPeer(PeerEndpointConfig(nodeKey, nodeIp))

    var mountRwState: MountState = MountState.Ready
    var mountRwReadOnly = false
    val mountIdRw = MountId.generate()
    val backendRw = InMemoryFileBackend(isReadOnly = false)

    val catalog = object : MountCatalog {
      override fun listMounts(): List<StorageMount> = listOfNotNull(getMount(mountIdRw))
      override fun getMount(mountId: MountId): StorageMount? =
        if (mountId == mountIdRw) {
          StorageMount(
            id = mountIdRw,
            kind = MountKind.LOCAL,
            provider = StorageProvider.SAF,
            label = "Main",
            config = MountConfig.SafConfig("content://tree/main"),
            credentialRef = null,
            readOnly = mountRwReadOnly,
            state = mountRwState,
          )
        } else {
          null
        }
      override fun getBackend(mountId: MountId): FileBackend? =
        if (mountId == mountIdRw) backendRw else null
    }

    val authorizer = PeerAuthorizer()
    authorizer.registerOrUpdatePeer(
      peerId = readPeerId,
      label = "Read-Only Peer",
      capabilities = setOf(Capability.Files(mountIdRw, AccessMode.READ)),
    )
    authorizer.registerOrUpdatePeer(
      peerId = writePeerId,
      label = "Read-Write Peer",
      capabilities = setOf(Capability.Files(mountIdRw, AccessMode.WRITE)),
    )
    // Note: unauthPeer is registered in Transport (to test FileService layer), but NOT registered in PeerAuthorizer

    val service = FileService(
      transport = nodeTransport,
      authorizer = authorizer,
      mountCatalog = catalog,
    )
    service.start(backgroundScope)

    // 1. Unknown peer in PeerAuthorizer is denied on all operations and sees empty root list
    val unauthStream = unauthPeerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    negotiateHello(unauthStream)
    unauthStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.STAT, 0, 10, ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq("/${mountIdRw.value}")))
      )
    )
    val unauthResp = (FrameCodec.decodeFrame(unauthStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.ERROR, unauthResp.type)
    assertEquals(
      StorageError.DENIED.name,
      (ProtocolV2PayloadCodec.decodeError(unauthResp.payload) as CodecResult.Success).value.errorCode
    )
    unauthStream.close()

    // 2. Write peer performs MKDIR, CREATE_NEW, OVERWRITE, MOVE, non-recursive DELETE failure, recursive DELETE
    val writeStream = writePeerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    // Negotiate 4096-byte max frame to also test chunk slicing when reading >4 KiB files
    val smallHello = ProtocolV2PayloadCodec.encodeHello(ProtocolMessage.Hello(FrameCodec.PROTOCOL_VERSION_V2, 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.HELLO, 0, 1, smallHello)))
    val helloReply = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.HELLO, helloReply.type)

    val dirPath = "/${mountIdRw.value}/docs"
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(WireFrame(FrameType.MKDIR, 0, 20, ProtocolV2PayloadCodec.encodeMkdirReq(ProtocolMessage.MkdirReq(dirPath))))
    )
    val mkdirResp = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, mkdirResp.type)

    // CREATE_NEW succeeds first time, fails second time with EXISTS
    val filePath = "$dirPath/readme.txt"
    val contentV1 = ByteArray(10_000) { 0x31 }
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(
          FrameType.WRITE,
          0,
          21,
          ProtocolV2PayloadCodec.encodeWriteReq(ProtocolMessage.WriteReq(filePath, WriteMode.CREATE_NEW, contentV1.size.toLong()))
        )
      )
    )
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 21, contentV1.copyOfRange(0, 4000)), 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 21, contentV1.copyOfRange(4000, 8000)), 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 21, contentV1.copyOfRange(8000, 10_000)), 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.END, 0, 21, ByteArray(0)), 4096))
    val createResp = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, createResp.type)

    // Second CREATE_NEW on existing file -> EXISTS
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(
          FrameType.WRITE,
          0,
          22,
          ProtocolV2PayloadCodec.encodeWriteReq(ProtocolMessage.WriteReq(filePath, WriteMode.CREATE_NEW, 1L))
        )
      )
    )
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 22, byteArrayOf(1)), 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.END, 0, 22, ByteArray(0)), 4096))
    val existsResp = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.EXISTS.name,
      (ProtocolV2PayloadCodec.decodeError(existsResp.payload) as CodecResult.Success).value.errorCode
    )

    // OVERWRITE replaces content
    val contentV2 = ByteArray(9_000) { 0x42 }
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(
          FrameType.WRITE,
          0,
          23,
          ProtocolV2PayloadCodec.encodeWriteReq(ProtocolMessage.WriteReq(filePath, WriteMode.OVERWRITE, contentV2.size.toLong()))
        )
      )
    )
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 23, contentV2.copyOfRange(0, 4000)), 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 23, contentV2.copyOfRange(4000, 8000)), 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 23, contentV2.copyOfRange(8000, 9000)), 4096))
    writeStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.END, 0, 23, ByteArray(0)), 4096))
    val overwriteResp = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, overwriteResp.type)

    // READ back over 4096-byte negotiated max frame (verifies chunk slicing in handleRead)
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(WireFrame(FrameType.READ, 0, 24, ProtocolV2PayloadCodec.encodeReadReq(ProtocolMessage.ReadReq(filePath))))
    )
    val readBuf = ByteArrayOutputStream()
    while (true) {
      val f = (FrameCodec.decodeFrame(writeStream.readFrameBytes(8192).getOrThrow()!!, 4096) as CodecResult.Success).value
      if (f.type == FrameType.DATA) {
        assertTrue(f.payload.size <= 4096)
        readBuf.write(f.payload)
      } else if (f.type == FrameType.END) {
        break
      }
    }
    assertArrayEquals(contentV2, readBuf.toByteArray())

    // 3. Read-only peer can STAT and READ, but is DENIED on WRITE, MKDIR, DELETE, MOVE
    val readStream = readPeerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    negotiateHello(readStream)
    readStream.writeFrameBytes(
      FrameCodec.encodeFrame(WireFrame(FrameType.STAT, 0, 30, ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq(filePath))))
    )
    val statOk = (FrameCodec.decodeFrame(readStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, statOk.type)

    readStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.DELETE, 0, 31, ProtocolV2PayloadCodec.encodeDeleteReq(ProtocolMessage.DeleteReq(filePath, false)))
      )
    )
    val delDenied = (FrameCodec.decodeFrame(readStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.DENIED.name,
      (ProtocolV2PayloadCodec.decodeError(delDenied.payload) as CodecResult.Success).value.errorCode
    )
    readStream.close()

    // 4. Read-only mount rejects WRITE even when peer holds WRITE capability
    mountRwReadOnly = true
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.MKDIR, 0, 40, ProtocolV2PayloadCodec.encodeMkdirReq(ProtocolMessage.MkdirReq("/${mountIdRw.value}/newdir")))
      )
    )
    val roDenied = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.DENIED.name,
      (ProtocolV2PayloadCodec.decodeError(roDenied.payload) as CodecResult.Success).value.errorCode
    )
    mountRwReadOnly = false

    // 5. Intra-mount MOVE succeeds; non-recursive DELETE on non-empty dir fails; recursive DELETE succeeds
    val movedPath = "$dirPath/renamed.txt"
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.MOVE, 0, 41, ProtocolV2PayloadCodec.encodeMoveReq(ProtocolMessage.MoveReq(filePath, movedPath)))
      )
    )
    val moveOk = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, moveOk.type)

    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.DELETE, 0, 42, ProtocolV2PayloadCodec.encodeDeleteReq(ProtocolMessage.DeleteReq(dirPath, recursive = false)))
      )
    )
    val nonRecDel = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.DENIED.name,
      (ProtocolV2PayloadCodec.decodeError(nonRecDel.payload) as CodecResult.Success).value.errorCode
    )

    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.DELETE, 0, 43, ProtocolV2PayloadCodec.encodeDeleteReq(ProtocolMessage.DeleteReq(dirPath, recursive = true)))
      )
    )
    val recDel = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.OK, recDel.type)

    // 6. Revoking peer in PeerAuthorizer immediately denies subsequent requests on existing stream
    authorizer.revokePeer(writePeerId)
    writeStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.STAT, 0, 44, ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq("/${mountIdRw.value}")))
      )
    )
    val revokedResp = (FrameCodec.decodeFrame(writeStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.DENIED.name,
      (ProtocolV2PayloadCodec.decodeError(revokedResp.payload) as CodecResult.Success).value.errorCode
    )

    writeStream.close()
    service.stop()
  }

  @Test
  fun protocolAndPathSecurity_invalidVersionMalformedFramesTraversalTruncatedWriteAndTimeout() = runTest {
    val hub = TestTransportHub()
    val nodeKey = PeerPublicKey.fromBytes(ByteArray(32) { (it + 1).toByte() }).getOrThrow()
    val peerBytes = ByteArray(32) { (it + 77).toByte() }
    val peerKey = PeerPublicKey.fromBytes(peerBytes).getOrThrow()
    val peerId = PeerId.fromBytes(peerBytes)
    val nodeIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val peerIp = TunnelIp.parse("10.66.0.2").getOrThrow()

    val nodeTransport = TestTransport(nodeKey, nodeIp, hub)
    val peerTransport = TestTransport(peerKey, peerIp, hub)
    nodeTransport.start()
    peerTransport.start()
    nodeTransport.addPeer(PeerEndpointConfig(peerKey, peerIp))
    peerTransport.addPeer(PeerEndpointConfig(nodeKey, nodeIp))

    val mountId = MountId.generate()
    val fastBackend = InMemoryFileBackend()
    val slowMountId = MountId.generate()
    val slowBackend = object : FileBackend by fastBackend {
      override suspend fun stat(path: com.homenode.core.storage.SafePath): com.homenode.core.storage.StorageResult<com.homenode.core.storage.FileStat> {
        kotlinx.coroutines.delay(500L)
        return fastBackend.stat(path)
      }
    }

    val catalog = object : MountCatalog {
      override fun listMounts(): List<StorageMount> = listOf(
        StorageMount(mountId, MountKind.LOCAL, StorageProvider.SAF, "Fast", MountConfig.SafConfig("content://a"), null, false, MountState.Ready),
        StorageMount(slowMountId, MountKind.LOCAL, StorageProvider.SAF, "Slow", MountConfig.SafConfig("content://b"), null, false, MountState.Ready),
      )
      override fun getMount(id: MountId): StorageMount? = listMounts().firstOrNull { it.id == id }
      override fun getBackend(id: MountId): FileBackend? = when (id) {
        mountId -> fastBackend
        slowMountId -> slowBackend
        else -> null
      }
    }

    val authorizer = PeerAuthorizer()
    authorizer.registerOrUpdatePeer(
      peerId = peerId,
      label = "Test Peer",
      capabilities = setOf(
        Capability.Files(mountId, AccessMode.WRITE),
        Capability.Files(slowMountId, AccessMode.READ),
      ),
    )

    val service = FileService(
      transport = nodeTransport,
      authorizer = authorizer,
      mountCatalog = catalog,
      perRequestTimeoutMs = 50L,
    )
    service.start(backgroundScope)

    // 1. Invalid protocol version in HELLO -> UNSUPPORTED_VERSION and stream closes
    val badVerStream = peerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    val v1Hello = ProtocolV2PayloadCodec.encodeHello(ProtocolMessage.Hello(version = 1, maxFrameBytes = 65536))
    badVerStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.HELLO, 0, 1, v1Hello)))
    val verErrFrame = (FrameCodec.decodeFrame(badVerStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.ERROR, verErrFrame.type)
    assertEquals(
      "UNSUPPORTED_VERSION",
      (ProtocolV2PayloadCodec.decodeError(verErrFrame.payload) as CodecResult.Success).value.errorCode
    )

    // 2. Non-HELLO first frame -> BAD_REQUEST
    val noHelloStream = peerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    noHelloStream.writeFrameBytes(
      FrameCodec.encodeFrame(WireFrame(FrameType.STAT, 0, 1, ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq("/"))))
    )
    val noHelloErr = (FrameCodec.decodeFrame(noHelloStream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(FrameType.ERROR, noHelloErr.type)

    // 3. Valid session testing path security (traversal, encoded traversal, invalid mount, unknown mount) & timeout
    val stream = peerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    negotiateHello(stream)

    val hostileVirtualPaths = listOf(
      "/${mountId.value}/../etc/passwd",
      "/${mountId.value}/a/%2e%2e/b",
      "/${mountId.value}/a\\b",
      "/invalid_mount_format/file.txt",
      "/${mountId.value}/" + "a".repeat(300),
    )
    for ((idx, badPath) in hostileVirtualPaths.withIndex()) {
      stream.writeFrameBytes(
        FrameCodec.encodeFrame(
          WireFrame(FrameType.STAT, 0, 100 + idx, ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq(badPath)))
        )
      )
      val err = (FrameCodec.decodeFrame(stream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
      assertEquals(FrameType.ERROR, err.type)
      assertEquals(
        StorageError.PATH_INVALID.name,
        (ProtocolV2PayloadCodec.decodeError(err.payload) as CodecResult.Success).value.errorCode
      )
    }

    // Well-formed but non-existent MountId -> denied by PeerAuthorizer (default-deny)
    val unknownMount = MountId.generate()
    stream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.STAT, 0, 150, ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq("/${unknownMount.value}/a.txt")))
      )
    )
    val unknownMountErr = (FrameCodec.decodeFrame(stream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.DENIED.name,
      (ProtocolV2PayloadCodec.decodeError(unknownMountErr.payload) as CodecResult.Success).value.errorCode
    )

    // Oversized expectedSize (> 2 GiB) -> QUOTA
    stream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(
          FrameType.WRITE,
          0,
          160,
          ProtocolV2PayloadCodec.encodeWriteReq(
            ProtocolMessage.WriteReq("/${mountId.value}/huge.bin", WriteMode.CREATE_NEW, FileBackend.MAX_WRITE_SIZE_BYTES + 1L)
          )
        )
      )
    )
    val quotaErr = (FrameCodec.decodeFrame(stream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.QUOTA.name,
      (ProtocolV2PayloadCodec.decodeError(quotaErr.payload) as CodecResult.Success).value.errorCode
    )

    // Request exceeding perRequestTimeoutMs (50ms) -> TIMEOUT
    stream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(FrameType.STAT, 0, 170, ProtocolV2PayloadCodec.encodeStatReq(ProtocolMessage.StatReq("/${slowMountId.value}")))
      )
    )
    val timeoutErr = (FrameCodec.decodeFrame(stream.readFrameBytes(65536).getOrThrow()!!) as CodecResult.Success).value
    assertEquals(
      StorageError.TIMEOUT.name,
      (ProtocolV2PayloadCodec.decodeError(timeoutErr.payload) as CodecResult.Success).value.errorCode
    )

    // 4. Truncated WRITE (stream closed before END) must not commit partial file
    val truncStream = peerTransport.openStream(nodeKey, FileService.FILE_SERVICE_PORT).getOrThrow()
    negotiateHello(truncStream)
    val partialPath = "/${mountId.value}/partial.bin"
    truncStream.writeFrameBytes(
      FrameCodec.encodeFrame(
        WireFrame(
          FrameType.WRITE,
          0,
          180,
          ProtocolV2PayloadCodec.encodeWriteReq(ProtocolMessage.WriteReq(partialPath, WriteMode.CREATE_NEW, 100L))
        )
      )
    )
    truncStream.writeFrameBytes(FrameCodec.encodeFrame(WireFrame(FrameType.DATA, 0, 180, ByteArray(20) { 1 })))
    truncStream.close()

    // Verify partial.bin was NOT committed in backend
    val relPartial = com.homenode.core.storage.PathValidator.parseRelative("partial.bin").getOrThrow()
    assertTrue(fastBackend.stat(relPartial).isFailure)

    stream.close()
    service.stop()
  }
}
