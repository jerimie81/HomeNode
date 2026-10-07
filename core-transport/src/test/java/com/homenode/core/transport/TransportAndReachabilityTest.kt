package com.homenode.core.transport

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportAndReachabilityTest {

  private fun sampleKey(seed: Byte): PeerPublicKey =
    PeerPublicKey.fromBytes(ByteArray(32) { (it + seed).toByte() }).getOrThrow()

  @Test
  fun tunnelIp_rejectsWildcardAndNon32Subnets() {
    assertTrue(TunnelIp.parse("0.0.0.0/0").isFailure)
    assertTrue(TunnelIp.parse("::/0").isFailure)
    assertTrue(TunnelIp.parse("10.66.0.2/24").isFailure)
    assertTrue(TunnelIp.parse("192.168.1.10/32").isFailure)

    val valid = TunnelIp.parse("10.66.0.2/32").getOrThrow()
    assertEquals("10.66.0.2", valid.address)
    assertEquals("10.66.0.2/32", valid.cidr32)
  }

  @Test
  fun testTransport_enforcesMutualPeerAuthCryptokeyRoutingAndRevocationTeardown() = runTest {
    val hub = TestTransportHub()
    val nodeKey = sampleKey(1)
    val peerKey = sampleKey(2)
    val unknownKey = sampleKey(3)
    val nodeIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val peerIp = TunnelIp.parse("10.66.0.2").getOrThrow()

    val nodeTransport = TestTransport(nodeKey, nodeIp, hub)
    val peerTransport = TestTransport(peerKey, peerIp, hub)
    nodeTransport.start()
    peerTransport.start()

    // Unregistered peer must fail
    assertTrue(peerTransport.openStream(nodeKey, 7001).isFailure)

    // Register peers mutually
    nodeTransport.addPeer(PeerEndpointConfig(peerKey, peerIp))
    peerTransport.addPeer(PeerEndpointConfig(nodeKey, nodeIp))

    // Cryptokey mismatch check
    assertTrue(nodeTransport.verifyCryptokeySource(peerIp, unknownKey).isFailure)
    assertEquals(peerKey, nodeTransport.verifyCryptokeySource(peerIp, peerKey).getOrThrow())

    // Accept loop on node (register listener channel before background collect)
    val incomingFlow = nodeTransport.listen(7001)
    val serverJob = backgroundScope.launch {
      incomingFlow.collect { incoming ->
        assertEquals(peerKey, incoming.remotePeer)
        val frame = incoming.readFrameBytes(1024).getOrThrow()
        if (frame != null) {
          incoming.writeFrameBytes(frame)
        }
      }
    }

    val stream = peerTransport.openStream(nodeKey, 7001).getOrThrow()
    val payload = "hello-homenode".encodeToByteArray()
    assertTrue(stream.writeFrameBytes(payload).isSuccess)
    val echoed = stream.readFrameBytes(1024).getOrThrow()
    assertArrayEquals(payload, echoed)

    // Revoking peer immediately tears down active streams
    nodeTransport.removePeer(peerKey)
    assertTrue(stream.isClosed)
    serverJob.cancel()
  }

  @Test
  fun wireGuardTransport_enforcesCryptokeySourceIpAndReportsStubStatus() = runTest {
    val nodeKey = sampleKey(10)
    val peerA = sampleKey(11)
    val peerB = sampleKey(12)
    val nodeIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val ipA = TunnelIp.parse("10.66.0.10").getOrThrow()

    val wg = WireGuardTransport(nodeKey, nodeIp)
    assertTrue(wg.isEngineStubbed)
    assertTrue(wg.addPeer(PeerEndpointConfig(peerA, ipA)).isSuccess)
    // Duplicate /32 IP for different peer must be rejected
    assertTrue(wg.addPeer(PeerEndpointConfig(peerB, ipA)).isFailure)
    assertEquals(peerA, wg.resolvePeerBySourceTunnelIp(ipA).getOrThrow())
  }

  @Test
  fun compositeReachability_worksOnLanOnlyWithoutInternet() = runTest {
    val composite = CompositeReachability(
      listOf(
        DirectLanReachability { listOf("192.168.1.50") },
        UpnpReachabilityStub(),
        StunReachabilityStub(),
      )
    )
    val hints = composite.discoverEndpoints(51820)
    assertEquals(1, hints.size)
    assertEquals("192.168.1.50", hints.first().hostIpLiteral)
    assertEquals(ReachabilityKind.DIRECT_LAN, hints.first().kind)
  }

  @Test
  fun tunnelSpikeHarness_benchmarksUserspaceAndKernelLoopbackEcho() = runTest {
    val hub = TestTransportHub()
    val serverKey = sampleKey(21)
    val clientKey = sampleKey(22)
    val serverIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val clientIp = TunnelIp.parse("10.66.0.2").getOrThrow()

    val serverTransport = TestTransport(serverKey, serverIp, hub)
    val clientTransport = TestTransport(clientKey, clientIp, hub)
    serverTransport.start()
    clientTransport.start()
    serverTransport.addPeer(PeerEndpointConfig(clientKey, clientIp))
    clientTransport.addPeer(PeerEndpointConfig(serverKey, serverIp))

    val incoming = serverTransport.listen(TunnelSpikeHarness.SPIKE_PORT)
    val echoJob = backgroundScope.launch {
      incoming.collect { stream ->
        while (!stream.isClosed) {
          val frame = stream.readFrameBytes(TunnelSpikeHarness.DEFAULT_CHUNK_BYTES).getOrElse { null } ?: break
          stream.writeFrameBytes(frame)
        }
      }
    }

    val userspaceRep = TunnelSpikeHarness.runEchoBenchmark(
      candidateName = "Option B Userspace Stream",
      serverTransport = serverTransport,
      clientTransport = clientTransport,
      iterations = 8,
    ).getOrThrow()
    assertTrue(userspaceRep.throughputMiBPerSec > 0.0)
    assertFalse(userspaceRep.occupiesAndroidVpnSlot)
    echoJob.cancel()

    val kernelRep = TunnelSpikeHarness.runKernelSocketLoopbackBenchmark(iterations = 8).getOrThrow()
    assertTrue(kernelRep.throughputMiBPerSec > 0.0)
    assertTrue(kernelRep.occupiesAndroidVpnSlot)
  }
}
