# ADR-001: Tunnel Engine Architecture (VpnService vs Userspace WireGuard + Netstack)

- **Status:** Accepted Architecture (Option B Selected for `:core-transport` Boundary; Native JNI/gomobile Engine Pending S8+ Hardware Verification)
- **Deciders:** User + HomeNode Lead Engineer
- **Slices Gated:** Slice T (Spike Harness), Slice S16 (`WireGuardTransport`)
- **Target Device:** Samsung Galaxy S8+ (`dream2lte` / `dream2qlte`, Exynos 8895 / Snapdragon 835, `arm64-v8a`, Android 9 / API 28, 4 GB RAM)

---

## 1. Context and Problem Statement

HomeNode requires an encrypted, peer-authenticated tunnel between paired client devices and the always-on Galaxy S8+ node, hosting `FileService` on tunnel port `7001` and `LanProxy` for allowlisted RFC1918 TCP targets. Upper modules (`:service-files`, `:service-node`, `:app`) must depend strictly on the `:core-transport` `Transport` interface (`openStream` / `listen` with authenticated `PeerPublicKey` derived via cryptokey routing) and never reference WireGuard library types.

Two implementation strategies were evaluated for `:core-transport`:
- **Option A (`com.wireguard.android:tunnel` + Android `VpnService`):** Creates a system-wide `/dev/tun` interface via `VpnService.Builder` and binds standard JVM `ServerSocket(InetAddress.getByName("10.66.0.1"), 7001)` on the TUN IP.
- **Option B (Userspace WireGuard + Embedded TCP/IP Netstack — `wireguard-go` `tun/netstack` or `boringtun` + `smoltcp`):** Runs WireGuard over an ordinary unprivileged UDP socket (`DatagramSocket(51820)`) and terminates peer TCP streams in-process without creating a system `VpnService`.

---

## 2. Option A vs Option B Comparison Matrix on Galaxy S8+ (API 28)

| Criterion | Option A: `VpnService` + `com.wireguard.android:tunnel` | Option B: Userspace WireGuard + Embedded Netstack |
|---|---|---|
| **Android Single-VPN Slot** | Occupies the phone's sole `VpnService` slot; requires interactive `VpnService.prepare()` dialog on first start and fails if another VPN is active. | Does **not** use `VpnService`; runs over standard UDP socket in `NodeService` foreground service, surviving headless `BOOT_COMPLETED` restarts without VPN dialogs. |
| **Peer Identity Attribution (`IncomingStream.remotePeer`)** | Kernel TCP `Socket.getInetAddress()` yields the source tunnel `/32` IPv4 (`10.66.0.x`), mapped via `WireGuardTransport.resolvePeerBySourceTunnelIp()` to `PeerPublicKey`. | Netstack stream directly yields the source tunnel `/32` IPv4 mapped via the cryptokey routing table (`peerByIp: Map<TunnelIp, PeerPublicKey>`). |
| **System Routing Blast Radius** | Must carefully restrict `VpnService.Builder.addRoute("10.66.0.0", 16)` and `addAllowedApplication(packageName)` to avoid hijacking the phone's internet or LAN traffic. | Zero impact on Android routing tables; `FileService` (7001) and `LanProxy` are the only listeners attached to the userspace netstack. |
| **64 KiB Chunk Streaming & Memory** | Uses Linux kernel TCP socket buffers (`TunnelSpikeHarness.runKernelSocketLoopbackBenchmark`). | Uses bounded 64 KiB in-process ring buffers (`TunnelSpikeHarness.runEchoBenchmark`) within the S8+'s 4 GB RAM budget. |
| **Native Binary / NDK Footprint** | ~1.2 MiB `libwg-go.so` (`arm64-v8a`). | ~2.8 MiB `.aar` / `libwg-netstack.so` (`arm64-v8a`). |

---

## 3. Decision

1. **Select Option B (Userspace WireGuard + Embedded Netstack)** as the target architecture behind `:core-transport`'s internal `WireGuardEngine` interface, because an always-on headless home node on Android 9 must start from `BootReceiver` -> `NodeService` without blocking on `VpnService` interactive consent or conflicting with device VPNs.
2. **Preserve Cryptokey Source-IP Routing Invariant:** Every peer in `WireGuardTransport` is assigned a unique `/32` `AllowedIPs` address in `10.66.0.0/16` (via `TunnelAddressAllocator`); `0.0.0.0/0` and prefixes `< /32` are rejected at both `TunnelIp.parse` and `WireGuardTransport.addPeer`.
3. **Truthfulness & Simulation Visibility:** Until the native `arm64-v8a` `wireguard-go` netstack JNI binary is linked and verified on the physical Galaxy S8+, `UserspaceWireGuardEngineStub` and `TestTransport` announce their stubbed status loudly in Logcat and surface a prominent **SIMULATION / STUB ADAPTERS ACTIVE** banner in the Compose UI.

---

## 4. How to Run the Slice T Spike on the Galaxy S8+ (API 28)

1. Run the automated spike unit test comparing in-process userspace streams vs real OS kernel TCP sockets:
   ```bash
   ./gradlew :core-transport:testDebugUnitTest --tests "com.homenode.core.transport.CoreTransportTest.tunnelSpikeHarness_benchmarksUserspaceAndKernelLoopbackEcho"
   ```
2. On the physical S8+, open the **Dashboard** tab and tap **"Run 64 KiB Stream Echo Benchmark"** to record both the in-process stream latency/throughput and the S8+ kernel TCP loopback baseline (P50 µs, P95 µs, MiB/s, and heap delta KiB).
