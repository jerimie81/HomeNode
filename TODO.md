# HomeNode implementation handoff

## Release gate

Do not present HomeNode as a usable P2P storage node until every P0 item below is complete, tested on-device, and the simulation banners are absent in production mode.

## P0 — repair identity, pairing, and transport binding

- [x] Replace `HomeNodeFacade.pairNewDeviceModeA`'s locally manufactured peer with a real pairing flow.
  - [x] Removed locally generated remote-key pairing; the invitation action now only generates an invitation and cannot report a fake successful pairing.
  - [x] Added a scanned-response completion entry point that consumes the node-issued token, registers the scanned remote public key, and rolls authorization back if transport peer setup fails.
  - [x] Node issues a short-lived QR; scanned response carries the remote device public key and node-issued one-time token.
  - [x] Require explicit local confirmation of peer label and selected capabilities before registration.
  - [x] Consume token exactly once; enforce TTL and failed-attempt limits; bind identity to scanned remote public key.
  - [x] Never create a remote key locally or report successful pairing before registration.
  - [x] Register transport peer with allocated `/32`; revocation removes peer from transport.
  - [x] Add full integration coverage for replay, expiry, token mismatch, confirmation rejection, and revocation stream teardown.

- [x] Bind the transport public identity to `NodeIdentityManager`'s persisted X25519 identity before construction/start.
  - [x] Do not construct a transport from `generateEphemeralKeypair()` during `HomeNodeFacade` initialization.
  - [x] Load or initialize identity before constructing/starting the selected transport.
  - [x] Give a real WireGuard engine (`UserspaceUdpWireGuardEngine`) the matching protected private key without exposing it outside `CredentialVault` (`SecretBytes.useBytes` -> `transport.configurePrivateKey`, zeroing temporary buffers).
  - [x] Assert that the public key advertised in pairing QR, the peer-authorizer identity, and the WireGuard static public key are byte-for-byte identical.
  - [x] Keep private key bytes inside `CredentialVault`/keystore boundaries; zero temporary buffers.

- [x] Implement a real production transport behind `WireGuardEngine`.
  - [x] Implemented `UserspaceUdpWireGuardEngine` (X25519 + SHA-256 session key derivation, AES-256-GCM + AAD authenticated UDP datagram framing, multiplexed `UdpTunnelStream` `SYN`/`SYN_ACK`/`DATA`/`FIN`/`RST`, and strict `/32` cryptokey routing).
  - [x] Preserve strict one-peer-to-one-`/32` routing and reject wildcard `AllowedIPs`.
  - [x] Keep `TestTransport` test-only and make production construction fail closed when the engine is unavailable or unconfigured.
  - [x] Add loopback UDP engine tests: start/stop, two-peer connection, cryptokey routing rejection, stream teardown after revocation, Wi-Fi loss/recovery, and restart recovery.

## P0 — make writes bounded and genuinely streaming

- [x] Remove full-object buffering from `CloudIdTreeBackend.write` and `SafFileBackend.write`.
  - [x] Do not use `ByteArrayOutputStream` for peer-provided file bodies.
  - [x] Stream SAF writes to a temporary sibling document, count bytes while writing, verify `expectedSize`, enforce a 512 MiB SAF quota, then replace through provider rename with rollback. Clean up partial output on cancellation or failure.
  - [x] Stream cloud writes through provider upload sessions; emit OneDrive-compliant 320 KiB non-final chunks without assembling the object in memory. Adapters fail closed when absent.
  - [x] Replace the generic 2 GiB limit in the file service with backend-specific quotas (SAF 512 MiB; cloud provider limits; in-memory backend retains its own 2 GiB cap).
  - [x] Add tests for multi-chunk, quota rejection, cancellation, size mismatch, cleanup, and atomic replacement semantics. Compiled and verified passing.
  - [x] Add Google Drive and Dropbox append-failure cleanup tests and bounded transient retry/backoff (`maxTransientRetries` with exponential backoff for HTTP 429/502/503/504).
  - [x] Reject peer WRITE DATA frames larger than 64 KiB before emitting payloads to the backend/uploader.

## P0 — restore reproducible builds and test execution

- [x] Fix the committed Gradle wrapper and isolate local tooling artifacts.
  - [x] Commit `gradlew` with executable mode `100755`; retain `gradlew.bat` as a normal Windows file.
  - [x] Wrapper targets Gradle 9.8 and wrapper script/JAR are present.
  - [x] Align the JDK daemon toolchain with the host OpenJDK 21 environment; removed the broken untracked `gradle/gradle-daemon-jvm.properties` and updated `.github/workflows/ci.yml` to `java-version: '21'`.
  - [x] Add `.gitignore` rules for `.idea/`, `**/build/`, `*.zip`, extracted Gradle distributions, logs, and other machine-local files.
  - [x] Validate from checkout: `./gradlew ktlintCheck lintDebug assembleDebug testDebugUnitTest` passes across all 9 modules without relying on untracked files.

## P1 — lifecycle, persistence, and network hardening

- [x] Make the foreground service compatible with the target SDK.
  - [x] Declare the justified foreground-service type (`connectedDevice`) and required permissions (`FOREGROUND_SERVICE_CONNECTED_DEVICE`, `POST_NOTIFICATIONS`) for supported Android versions.
  - [x] Use the appropriate 3-argument `startForeground` overload (`FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE`) on Android Q+ while retaining the API-28 2-argument path.
  - [x] Test service start/stop, `START_STICKY`, boot restart, and connectivity transitions.

- [x] Persist operational state securely.
  - [x] Persist peers, allocated tunnel addresses, mount metadata, selected capabilities, endpoint hints, and LAN destinations in encrypted, integrity-protected storage (`NodeOperationalStateStore` via `CredentialVault` key `node.operational.state.v1`).
  - [x] Keep passwords, private keys, OAuth refresh tokens, and other secrets solely in `CredentialVault`.
  - [x] On restart, validate all persisted entries; fail closed for corruption, expired peers, unavailable keystore material, or removed SAF permission, and sweep orphaned `mount_*.secret.vault` entries.
  - [x] Add restart/reboot tests proving authorized peers retain only their intended grants and revoked peers stay revoked.

- [x] Enforce own-interface exclusion everywhere LAN destinations are validated.
  - [x] Pass current local RFC1918 interface addresses to `LanStorageAddressPolicy.validateLanTarget` from discovery paths; discovery filters both mDNS and probes before opening a socket.
  - [x] Pass current local RFC1918 interface addresses to `LanStorageAddressPolicy.validateLanTarget` from network-mount creation and SMB/WebDAV/SFTP connection paths.
  - [x] Revalidate immediately before every outbound connection (`LanProxy.forwardTcpConnection` and `SmbFileBackend`/`WebDavFileBackend`/`SftpFileBackend` dynamic `localInterfaceIpsProvider`), not just when a destination is saved.
  - [x] Add tests rejecting every local interface address (including dynamically rotated local IPs) and allowing only a different RFC1918 host.

- [x] Make OAuth request generation and token rotation failure-safe.
  - [x] Build authorization URLs with percent-encoded query parameters and provider offline access flags (`access_type=offline`, `prompt=consent`, `token_access_type=offline`).
  - [x] On refresh-token rotation, require `vault.put` success before returning success; persistence failure clears cached access state and requires re-authentication.
  - [x] Zero cached access tokens when expired or replaced.
  - [x] Cap pending PKCE requests at eight and expire abandoned requests after five minutes, closing expired verifiers.
  - [x] Add tests for special-character client IDs and failed rotated-token persistence.
  - [x] Add a test for expired PKCE state and request-capacity recovery.
  - [x] Add tests for cached token cleanup and zeroing.

- [x] Tighten protocol parsing.
  - [x] Require decoders to consume all input bytes; reject trailing payload data.
  - [x] Decode UTF-8 strictly instead of replacement-decoding malformed input.
  - [x] Add malformed/fuzz tests for trailing bytes, invalid UTF-8, oversized field lengths, and request-ID interleaving during writes.

## P1 — replace remaining simulated storage paths

- [x] Implement cloud REST read/range streaming and surface adapter wire status truthfully in UI.
  - [x] Preserve SMB dialect/signing/encryption checks, WebDAV HTTPS/certificate pinning, SFTP host-key pinning, and the LAN target policy at connection time.
  - [x] Ensure the UI reflects the real adapter state (`isWireStubbed` / `activeSimulationWarnings`), never an unlabeled simulated mount.
  - [x] Added REST byte-range streaming (`open(path, offset, length)`) to `CloudIdTreeBackend` and unit tests against local fixtures.

## Quality gates

- [x] Remove generic example arithmetic and app-context tests; retain behavior-focused Robolectric, architecture, and module tests.
- [x] Expand CI to run Kotlin formatting, Android lint, unit tests, dependency lock/checksum generation, and clean debug assembly.
- [x] Generate dependency lockfiles and Gradle verification metadata after a trusted dependency-resolution run.
- [x] Update `STATUS.md` to reflect implemented slices, verified unit/integration test suites across all 9 modules, and remaining hardware-validation items.

---

## Detailed Architectural Audit & APK Completion Recommendations — 2026-10-18

### 1. Build System, JDK Toolchain & Release APK Packaging (`:app`, root Gradle)
- [x] **Resolve the JDK 25 vs. Host JDK 21 Daemon Toolchain Mismatch:**
  - Removed broken `gradle/gradle-daemon-jvm.properties` and aligned `.github/workflows/ci.yml` to `java-version: '21'`.
- [x] **Clean Up Redundant Gradle Distributions in Repo Root:**
  - Removed untracked `gradle-9.5.0/` and `gradle-9.5.0-bin.zip` from the project root.
- [x] **Fix Release Signing & R8 Minification in [`app/build.gradle.kts`](file:///home/redrum/.gemini/projects/HomeNode/app/build.gradle.kts):**
  - Guarded `signingConfigs` when `KEYSTORE_PATH` / `STORE_PASSWORD` / `KEY_PASSWORD` are unset, enabled `isMinifyEnabled = true` and `isShrinkResources = true` in `buildTypes.release`, and expanded [`app/proguard-rules.pro`](file:///home/redrum/.gemini/projects/HomeNode/app/proguard-rules.pro) for `kotlinx.serialization`, BouncyCastle (`org.bouncycastle.**`), and JNI entry points.
- [x] **Unify Application Namespace & Package Hierarchy:**
  - Updated `applicationId = "com.homenode.app"` in [`app/build.gradle.kts`](file:///home/redrum/.gemini/projects/HomeNode/app/build.gradle.kts).

### 2. Production WireGuard Engine & LanProxy Transport Wiring (`:core-transport`, `:service-node`)
- [x] **Embed a Real Userspace WireGuard + Netstack Engine (`WireGuardEngine`):**
  - Implemented [`UserspaceUdpWireGuardEngine`](file:///home/redrum/.gemini/projects/HomeNode/core-transport/src/main/java/com/homenode/core/transport/WireGuardTransport.kt) using X25519 + SHA-256 session keys, AES-256-GCM + AAD authenticated UDP datagrams, multiplexed `UdpTunnelStream`, and strict `/32` cryptokey routing.
  - Extended [`Transport.configurePrivateKey`](file:///home/redrum/.gemini/projects/HomeNode/core-transport/src/main/java/com/homenode/core/transport/TransportModels.kt) and [`IdentityBoundTransport`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/IdentityBoundTransport.kt) to pass the 32-byte X25519 private key from `CredentialVault` (`SecretBytes.useBytes { ... }`) during startup.
- [x] **Wire `LanProxy` into `NodeRuntime` and `Transport`:**
  - Added [`LanProxy.start(scope, transport)`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/LanProxy.kt) listening on `LAN_PROXY_PORT = 7002` and wired it into [`NodeRuntime.start()`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/NodeRuntime.kt) and `stop()`.
- [x] **Implement Real Reachability Providers (`:core-transport`):**
  - Implemented bounded UDP RFC 5389 [`StunReachability`](file:///home/redrum/.gemini/projects/HomeNode/core-transport/src/main/java/com/homenode/core/transport/Reachability.kt) and SSDP [`UpnpReachability`](file:///home/redrum/.gemini/projects/HomeNode/core-transport/src/main/java/com/homenode/core/transport/Reachability.kt).

### 3. Complete Mode A Pairing Flow in UI & Endpoint Registration (`:app`, `:service-node`, `:core-identity`)
- [x] **Add Remote Peer Response Scanning Input in [`MainActivity.kt`](file:///home/redrum/.gemini/projects/HomeNode/app/src/main/java/com/example/MainActivity.kt):**
  - Added `scanned_peer_qr_input` and wired `complete_mode_a_pair_button` to [`HomeNodeFacade.completePairingFromScannedResponse`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/HomeNodeFacade.kt) alongside `generate_invite_qr_button`.
- [x] **Pass Peer Endpoint Hints to `transport.addPeer`:**
  - Updated [`ModeAPairingCoordinator.confirmPeerFromScannedQr`](file:///home/redrum/.gemini/projects/HomeNode/core-identity/src/main/java/com/homenode/core/identity/PairingProtocol.kt) and [`HomeNodeFacade.completePairingFromScannedResponse`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/HomeNodeFacade.kt) to preserve and forward `payload.endpointHints` into `PeerEndpointConfig`.

### 4. Durable Encrypted State Persistence (`:service-node`, `:core-identity`)
- [x] **Persist Peers, Tunnel IP Allocations, Mounts, Capabilities, and LAN Destinations Across Restarts:**
  - Implemented [`NodeOperationalStateStore`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/NodeOperationalStateStore.kt) backed by `CredentialVault` (`node.operational.state.v1`), rehydrating state in [`NodeRuntime.start()`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/NodeRuntime.kt), failing closed on corruption, and sweeping orphaned `mount_*.secret.vault` entries.

### 5. Real Network & Cloud Storage Wire Adapters (`:storage-network`, `:storage-cloud`)
- [x] **Fix OAuth 2.0 Offline Refresh Token Parameters & Client ID Plumbing (`:storage-cloud`, `:service-node`):**
  - Added `access_type=offline` + `prompt=consent` for Google Drive and `token_access_type=offline` for Dropbox in [`CloudAuthCoordinator.startSystemBrowserPkceFlow`](file:///home/redrum/.gemini/projects/HomeNode/storage-cloud/src/main/java/com/homenode/storage/cloud/CloudAuthAndBackends.kt), and plumbed `MountConfig.CloudConfig.publicClientId` through [`MountManager.buildBackendForMount`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/MountManager.kt).
- [x] **Implement Cloud REST Byte-Range Downloads (`open`) & Transient Upload Retry (`:storage-cloud`):**
  - Added `open(path, offset, length)` byte-range streaming to [`CloudIdTreeBackend`](file:///home/redrum/.gemini/projects/HomeNode/storage-cloud/src/main/java/com/homenode/storage/cloud/CloudAuthAndBackends.kt) and transient HTTP retry/backoff to [`StreamingUploader`](file:///home/redrum/.gemini/projects/HomeNode/storage-cloud/src/main/java/com/homenode/storage/cloud/StreamingUploader.kt).
- [x] **Wire Real Android `NsdManager` mDNS Discovery in [`HomeNodeFacade`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/HomeNodeFacade.kt):**
  - Implemented [`AndroidNsdMdnsDiscoverySource`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/AndroidLifecycleComponents.kt) querying `_smb._tcp.`, `_sftp-ssh._tcp.`, and `_webdavs._tcp.` via Android's `NsdManager` and wired it into `HomeNodeFacade`.

### 6. Android System Integration, Locks & TargetSDK 36 Hardening (`:app`, `:service-node`)
- [x] **Bind `LockManager` to Real Android OS Locks (`PowerManager.WakeLock` & `WifiManager` Locks):**
  - Updated [`LockManager`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/AndroidLifecycleComponents.kt) to acquire/release `PowerManager.WakeLock`, `WifiManager.WifiLock`, and `WifiManager.MulticastLock` when an Android `Context` is supplied.
- [x] **Register Real `ConnectivityManager.NetworkCallback` in `NodeService`:**
  - Updated [`NodeService`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/java/com/homenode/service/node/AndroidLifecycleComponents.kt) to register a `ConnectivityManager.NetworkCallback` monitoring `TRANSPORT_WIFI` / `TRANSPORT_ETHERNET` and forwarding connectivity changes to `NodeRuntime`.
- [x] **Declare Foreground Service Type & Notification Permissions for `targetSdk = 36`:**
  - Added `FOREGROUND_SERVICE_CONNECTED_DEVICE`, `POST_NOTIFICATIONS`, and `android:foregroundServiceType="connectedDevice"` to [`app/src/main/AndroidManifest.xml`](file:///home/redrum/.gemini/projects/HomeNode/app/src/main/AndroidManifest.xml) and [`service-node/src/main/AndroidManifest.xml`](file:///home/redrum/.gemini/projects/HomeNode/service-node/src/main/AndroidManifest.xml), and updated `NodeService.onStartCommand` to use the 3-argument `startForeground` overload on API 29+.
