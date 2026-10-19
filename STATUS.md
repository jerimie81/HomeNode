# HomeNode — Component & Slice Status

## Current implementation update — 2026-10-18

- **Build & Toolchain Verification:** Removed the broken untracked `gradle/gradle-daemon-jvm.properties` (which pinned JDK 25 via dead Foojay URLs) and redundant `gradle-9.5.0*` artifacts. Aligned `.github/workflows/ci.yml` to OpenJDK 21. Verified clean execution of `./gradlew ktlintCheck lintDebug assembleDebug testDebugUnitTest` across all 9 modules (`:app`, `:service-node`, `:service-files`, `:core-transport`, `:core-identity`, `:core-storage`, `:storage-local`, `:storage-network`, `:storage-cloud`).
- **Identity, Pairing, and Userspace UDP Tunnel Engine (`:core-identity`, `:core-transport`, `:service-node`, `:app`):**
  - Implemented `UserspaceUdpWireGuardEngine` in `WireGuardTransport.kt` using X25519 + SHA-256 session key derivation, AES-256-GCM + AAD authenticated UDP datagrams, multiplexed `UdpTunnelStream` (`SYN`, `SYN_ACK`, `DATA`, `FIN`, `RST`), and strict `/32` cryptokey source-IP routing.
  - Bound the node's persisted 32-byte X25519 private key from `CredentialVault` to `IdentityBoundTransport` via `SecretBytes.useBytes { transport.configurePrivateKey(it) }` during runtime startup, and verified byte-for-byte public key equality across `NodeIdentityManager`, `PairingPayload`, and `Transport`.
  - Updated `ModeAPairingCoordinator` and `HomeNodeFacade.completePairingFromScannedResponse` to preserve and forward scanned peer `endpointHints` into `PeerEndpointConfig`, and wired the `PeersAndPairingTab` UI in `MainActivity.kt` (`scanned_peer_qr_input` + `complete_mode_a_pair_button`).
- **Durable Encrypted State Persistence (`:service-node`, `:core-identity`):**
  - Implemented `NodeOperationalStateStore` encrypting and authenticating `PeerRecord`s, `/32` tunnel IP allocations, `StorageMount`s, and `LanDestination`s in `CredentialVault` (`node.operational.state.v1`).
  - `NodeRuntime.start()` rehydrates persisted operational state, restores active `/32` peer routes, fails closed (`ERROR_FATAL`) on state corruption, and sweeps orphaned `mount_*.secret.vault` files.
- **LanProxy Listener & Dynamic Own-Interface Exclusion (`:service-node`, `:storage-network`):**
  - Wired `LanProxy.start(scope, transport)` on `LAN_PROXY_PORT = 7002` inside `NodeRuntime.start()`/`stop()`.
  - Enforced dynamic own-interface RFC1918 exclusion immediately before every outbound connection in `LanProxy.forwardTcpConnection` and `SmbFileBackend`/`WebDavFileBackend`/`SftpFileBackend`.
- **Cloud OAuth Hardening, Byte-Range Streaming & Transient Upload Retry (`:storage-cloud`, `:service-node`):**
  - Added `access_type=offline` + `prompt=consent` for Google Drive and `token_access_type=offline` for Dropbox in `CloudAuthCoordinator.startSystemBrowserPkceFlow`, plumbed `MountConfig.CloudConfig.publicClientId` through `MountManager`, and added unit tests verifying cached access token zeroing on rotation/expiry.
  - Added bounded transient HTTP retry with exponential backoff (`maxTransientRetries`, `retryBackoffMillis` for HTTP 429/502/503/504) to `StreamingUploader` and `open(path, offset, length)` byte-range streaming to `CloudIdTreeBackend`.
- **Android System Integration & TargetSDK 36 Hardening (`:service-node`, `:app`, `:storage-local`):**
  - Wired real `PowerManager.WakeLock` and `WifiManager` (`WifiLock`, `MulticastLock`) into `LockManager`, `ConnectivityManager.NetworkCallback` into `NodeService`, and `AndroidNsdMdnsDiscoverySource` (`NsdManager`) into `HomeNodeFacade`.
  - Declared `FOREGROUND_SERVICE_CONNECTED_DEVICE`, `POST_NOTIFICATIONS`, and `android:foregroundServiceType="connectedDevice"` in manifests, and guarded API 29 `StorageManager.getStorageVolume(Uri)` and `DocumentsContract.isChildDocument` calls in `AndroidContentResolverSafTreeAdapter` for API 28 compatibility.

Truthfulness vocabulary: `implemented · tested · partial · stubbed · blocked`.

## Remedial Fixes Applied (Ordered per User Audit)

| # | Audit Finding | Fix Applied | Status |
|---|---|---|---|
| **1** | Node public key was `SHA-256(privateKey)`, not X25519 | Added vetted `org.bouncycastle:bcprov-jdk18on` (`org.bouncycastle.math.ec.rfc7748.X25519`). `NodeIdentityManager` performs real RFC 7748 X25519 basepoint scalar multiplication (`scalarMultBase`) and DH shared-secret derivation (`scalarMult`) with constant-time all-zero low-order point rejection, verified against RFC 7748 §6.1 test vectors. | `tested` |
| **2** | Vault ran on `SoftwareAesGcmTestWrapper`; no S8+ instrumented test | `KeystoreCredentialVault` & `HomeNodeFacade` wire `AesGcmKeyWrapper.createDefault()` which uses `AndroidKeystoreAesGcmWrapper` (`AndroidKeyStore` AES-256-GCM without StrongBox) on Android devices and falls back to `SoftwareAesGcmTestWrapper` only in host-JVM unit tests. Added S8+ instrumented test `AndroidKeystoreVaultInstrumentedTest` in `:core-identity/src/androidTest`. | `tested` |
| **3** | `HomeNodeFacade` had a fake OAuth endpoint returning `"access_..."` and seeded fake mounts; no simulation banner | Removed the fake OAuth endpoint and all pre-seeded fake mounts. Added `HttpsOAuthTokenEndpointAdapter` (`HttpsURLConnection` with 10s connect / 15s read timeout, 64 KiB cap, zero client secret) + system browser `Intent.ACTION_VIEW` & `com.homenode.oauth:/oauth2redirect` callback handler. Added prominent top-level `SIMULATION / STUB ADAPTERS ACTIVE` warning banner (`testTag = "simulation_warning_banner"`). | `tested` |
| **4** | Mounts wired only to `FakeSafTreeAdapter`; no `DocumentsContract` code | Created `AndroidContentResolverSafTreeAdapter` in `:storage-local` using `DocumentsContract` and `StorageManager` volume state checks (guarded for API 28+). Wired `ActivityResultContracts.OpenDocumentTree()` + `takePersistableUriPermission` in `MainActivity`. | `tested` |
| **5** | `LanProxy` was only a policy check; `NodeService` didn't start runtime; hardcoded `192.168.1.42`; ADR-001 spike | Added real TCP socket forwarding (`LanProxy.forwardTcpConnection`) and tunnel listener on port `7002` (`LanProxy.start`), with zero-DNS `InetAddress.getByAddress`, per-peer (`4`) and global (`16`) concurrency caps, 5s connect timeout, and 30s socket idle timeout. Wired `NodeService` to start/stop `NodeRuntime` and monitor `ConnectivityManager.NetworkCallback`. | `tested` |

---

## Slice Roadmap Status

| Slice | Scope | Status | Notes / Active Stubs |
|---|---|---|---|
| **S0** | Multi-module bootstrap, ADRs 001–011, CI, `ArchitectureDependencyTest` | `tested` | 9-module strict DAG enforced and verified |
| **T** | Hardware tunnel spike checklist & `TunnelSpikeHarness` (ADR-001) | `tested` | Benchmarks Option B (in-process stream) vs Option A (OS kernel TCP loopback socket); ADR-001 documented |
| **S1** | `:core-storage` & `:core-transport` contracts, `InMemoryFileBackend`, `TestTransport` | `tested` | Full contract test suites passing in `:core-storage` & `:core-transport` |
| **S2** | `NodeRuntime` state machine, `RetryPolicy` (1→60s), `SafeEventLogger` | `tested` | Virtual-time backoff, deduplication, and 2m reset tests passing |
| **S3** | Real RFC 7748 X25519 identity + `AndroidKeystoreAesGcmWrapper` (`KeystoreCredentialVault`) | `tested` | RFC 7748 §6.1 vectors passing |
| **S4** | `PeerAuthorizer` (`Files`/`Lan` capabilities), `/32` `TunnelAddressAllocator` | `tested` | Default-deny; `MountKind.CLOUD` excluded from default grants; persisted across restarts via `NodeOperationalStateStore` |
| **S5** | `PathValidator` corpus/fuzz, `FrameCodec`, Protocol v2, `FileService` (port 7001) | `tested` | Two-runtime integration test, trailing-byte/invalid-UTF-8/interleaved-WRITE fuzz tests passing |
| **S6** | `MountManager`, per-mount state/retry, capability & vault wipe on removal | `tested` | Enforces `readOnly` cap, cross-mount `MOVE` rejection (`UNSUPPORTED`), and orphan vault secret sweep |
| **S7** | Local storage (`SafFileBackend` + `AndroidContentResolverSafTreeAdapter` in `:storage-local`) | `tested` | Real `DocumentsContract` hop-by-hop resolution, sibling staging streaming writes (512 MiB cap), `OpenDocumentTree` picker |
| **S8** | `LanProxy` + `LanStorageAddressPolicy` + real TCP socket forwarder (port 7002) | `tested` | Config-time + connect-time SSRF & own-interface checks, 20/min rate limit, 4/peer concurrency cap, 5s/30s timeouts |
| **S9** | Network storage core: `SmbFileBackend` (SMB 2/3 only) + vault integration | `partial` / `tested` | Policy, dynamic own-interface revalidation & contract `tested`; wire library adapter (`isWireStubbed`) surfaced in UI |
| **S10** | `NetworkDiscovery` (`AndroidNsdMdnsDiscoverySource` + bounded RFC1918 `/24` real TCP socket probe) | `tested` | Max 254 hosts, 16 concurrency, 400ms connect, 15s deadline, 10s cooldown, own-interface filtering |
| **S11** | `WebDavFileBackend` (HTTPS-first, cert pin) & `SftpFileBackend` (TOFU host-key pin) | `partial` / `tested` | Pinning, dynamic own-interface revalidation & policy boundaries `tested`; wire transport adapters (`isWireStubbed`) surfaced in UI |
| **S12** | Cloud auth (`CloudAuthCoordinator` + `HttpsOAuthTokenEndpointAdapter` + browser redirect) | `tested` | Offline access parameters (`access_type=offline`, `prompt=consent`, `token_access_type=offline`), token zeroing, fail-closed rotation |
| **S13** | Google Drive backend (`CloudIdTreeBackend`: `drive.file` default, resumable upload, byte-range `open`) | `tested` | Resumable upload HTTP adapter, transient retry/backoff, and `open(path, offset, length)` byte-range streaming `tested` |
| **S14** | OneDrive backend (Graph API, 320 KiB upload session chunk alignment, byte-range `open`) | `tested` | Upload-session HTTP adapter, transient retry/backoff, and `open(path, offset, length)` byte-range streaming `tested` |
| **S15** | Dropbox backend (API v2, App-Folder default, upload session streaming, byte-range `open`) | `tested` | Upload-session HTTP adapter, transient retry/backoff, and `open(path, offset, length)` byte-range streaming `tested` |
| **S16** | `WireGuardTransport` (`/32` `AllowedIPs`, source-IP cryptokey routing, `UserspaceUdpWireGuardEngine`) | `tested` | Real loopback UDP X25519 + AES-256-GCM tunnel engine & `/32` cryptokey routing `tested` |
| **S17** | Pairing (`PairingPayloadParser`, `ModeAPairingCoordinator` single-use QR with real X25519 keys) | `tested` | Mode A scanned peer completion, replay/expiry/mismatch rejection, and endpoint hint forwarding `tested` |
| **S18** | Android lifecycle (`NodeService`, `BootReceiver`, `LockManager`, `LanInterfaceDetector`) | `tested` | API 28 + API 29+ `connectedDevice` foreground service, OS WakeLock/WifiLock/MulticastLock, `NetworkCallback` `tested` |
| **S19** | `Reachability` (`DirectLanReachability`, `StunReachability`, `UpnpReachability`, `CompositeReachability`) | `tested` | Real `NetworkInterface` LAN IP discovery, RFC 5389 UDP STUN binding client, and SSDP `M-SEARCH` probe `tested` |
| **S20** | Jetpack Compose UI (`DashboardTab`, `StorageMountsTab`, `PeersAndPairingTab`, `LanAndSecurityTab`) | `tested` | Prominent `SIMULATION / STUB ADAPTERS ACTIVE` banner, scanned QR pairing completion input, SAF picker, system browser PKCE |
| **S21** | Hardening: Threat-model verification matrix (`TM-01`..`TM-07`), fuzz test, log audit, R8 rules | `tested` | All 9 modules pass `ktlintCheck`, `lintDebug`, `testDebugUnitTest`, and `assembleDebug` |
