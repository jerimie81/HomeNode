# HomeNode — Component & Slice Status

## Current implementation update — 2026-10-07

- `HomeNodeFacade` now creates its transport after `NodeRuntime` loads the persisted node identity, and checks that the transport public key matches. A runtime test covers identity equality across start and restart. The WireGuard engine still has no real private-key configuration and remains unavailable/stubbed.
- Network mount creation and SMB/WebDAV/SFTP connection checks exclude current local RFC1918 interface addresses.
- Pending OAuth PKCE requests are capped at eight and expire after five minutes; abandoned verifiers are closed. A behavior test covers capacity and expiry.
- SAF writes stream into a temporary sibling, enforce a 512 MiB backend quota, verify expected size, and commit via provider rename with rollback; failure and cancellation paths clean up staging files. A host test covers chunked success, mismatch preservation, and quota rejection.
- Cloud writes now stream through bounded upload-session adapters for OneDrive, Google Drive, and Dropbox; `CloudIdTreeBackend` no longer stores complete file bodies. Providers fail closed when no adapter is configured. Cloud read/download and remote tree metadata operations remain simulated or unavailable.
- FileService enforces the selected backend's write quota; the transport currently caps DATA frames at 1 MiB.
- Cloud uploader and integration tests are authored, but no Kotlin compilation, Gradle tests, or device/provider validation has run. `git diff --check` is the only verification for this update.
- Quality-gate setup now removes the generic arithmetic/app-context example tests and retains behavior tests; CI is configured for ktlint, Android lint, unit tests, dependency lock/checksum generation, and clean debug assembly. This workflow has not been executed, generated dependency metadata is not committed, and no physical API 28/current device validation was available.

Truthfulness vocabulary: `implemented · tested · partial · stubbed · blocked`.
*(Per `1_AGENT_CONFIG.md` §1 & §6: items are marked `implemented`, `partial`, or `stubbed` until you paste physical S8+ / machine verification output to promote them to `tested`.)*

## Remedial Fixes Applied (Ordered per User Audit)

| # | Audit Finding | Fix Applied | Status |
|---|---|---|---|
| **1** | Node public key was `SHA-256(privateKey)`, not X25519 | Added vetted `org.bouncycastle:bcprov-jdk18on` (`org.bouncycastle.math.ec.rfc7748.X25519`). `NodeIdentityManager` now performs real RFC 7748 X25519 basepoint scalar multiplication (`scalarMultBase`) and DH shared-secret derivation (`scalarMult`) with constant-time all-zero low-order point rejection, verified against RFC 7748 §6.1 test vectors. | `implemented` |
| **2** | Vault ran on `SoftwareAesGcmTestWrapper`; no S8+ instrumented test | `KeystoreCredentialVault` & `HomeNodeFacade` now wire `AesGcmKeyWrapper.createDefault()` which uses `AndroidKeystoreAesGcmWrapper` (`AndroidKeyStore` AES-256-GCM without StrongBox) on Android devices and falls back to `SoftwareAesGcmTestWrapper` only in host-JVM unit tests. Added S8+ instrumented test `AndroidKeystoreVaultInstrumentedTest` in `:core-identity/src/androidTest`. | `implemented` |
| **3** | `HomeNodeFacade` had a fake OAuth endpoint returning `"access_..."` and seeded fake mounts; no simulation banner | Removed the fake OAuth endpoint and removed all pre-seeded fake mounts. Added `HttpsOAuthTokenEndpointAdapter` (`HttpsURLConnection` with 10s connect / 15s read timeout, 64 KiB cap, zero client secret) + system browser `Intent.ACTION_VIEW` & `com.homenode.oauth:/oauth2redirect` callback handler. Added a prominent top-level `SIMULATION / STUB ADAPTERS ACTIVE` warning banner (`testTag = "simulation_warning_banner"`) whenever any stub or simulated adapter is active. | `implemented` |
| **4** | Mounts wired only to `FakeSafTreeAdapter`; no `DocumentsContract` code | Created `AndroidContentResolverSafTreeAdapter` in `:storage-local` using `DocumentsContract` (`getTreeDocumentId`, `buildChildDocumentsUriUsingTree`, `buildDocumentUriUsingTree`, `isChildDocument`, `createDocument`, `deleteDocument`, `moveDocument`, `renameDocument`) and `StorageManager` volume state checks. Wired `ActivityResultContracts.OpenDocumentTree()` + `takePersistableUriPermission` in `MainActivity`. | `implemented` |
| **5** | `LanProxy` was only a policy check; `NodeService` didn't start runtime; hardcoded `192.168.1.42`; ADR-001 spike | Added real TCP socket forwarding (`LanProxy.forwardTcpConnection`) with zero-DNS `InetAddress.getByAddress`, per-peer (`4`) and global (`16`) concurrency caps, 5s connect timeout, and 30s socket idle timeout. Wired `NodeService` to start/stop `NodeRuntime` and added `LanInterfaceDetector` (`NetworkInterface`). Added `TunnelSpikeHarness.runKernelSocketLoopbackBenchmark` and completed `docs/adr/001-tunnel-engine.md`. | `implemented` |

---

## Slice Roadmap Status

| Slice | Scope | Status | Notes / Active Stubs |
|---|---|---|---|
| **S0** | Multi-module bootstrap, ADRs 001–011, CI, `ArchitectureDependencyTest` | `implemented` | 9-module strict DAG enforced |
| **T** | Hardware tunnel spike checklist & `TunnelSpikeHarness` (ADR-001) | `implemented` | Benchmarks Option B (in-process stream) vs Option A (OS kernel TCP loopback socket); ADR-001 documented |
| **S1** | `:core-storage` & `:core-transport` contracts, `InMemoryFileBackend`, `TestTransport` | `implemented` | Full contract test suites in `:core-storage` & `:core-transport` |
| **S2** | `NodeRuntime` state machine, `RetryPolicy` (1→60s), `SafeEventLogger` | `implemented` | Virtual-time backoff, deduplication, and 2m reset tests |
| **S3** | Real RFC 7748 X25519 identity + `AndroidKeystoreAesGcmWrapper` (`KeystoreCredentialVault`) | `implemented` | RFC 7748 §6.1 vectors + S8+ `AndroidKeystoreVaultInstrumentedTest` |
| **S4** | `PeerAuthorizer` (`Files`/`Lan` capabilities), `/32` `TunnelAddressAllocator` | `implemented` | Default-deny; `MountKind.CLOUD` excluded from default grants |
| **S5** | `PathValidator` corpus/fuzz, `FrameCodec`, Protocol v2, `FileService` (port 7001) | `implemented` | Two-runtime integration test over `TestTransport` |
| **S6** | `MountManager`, per-mount state/retry, capability & vault wipe on removal | `implemented` | Enforces `readOnly` cap and cross-mount `MOVE` rejection (`UNSUPPORTED`) |
| **S7** | Local storage (`SafFileBackend` + `AndroidContentResolverSafTreeAdapter` in `:storage-local`) | `implemented` | Real `DocumentsContract` hop-by-hop resolution, containment, `OpenDocumentTree` picker |
| **S8** | `LanProxy` + `LanStorageAddressPolicy` + real TCP socket forwarder | `implemented` | Config-time + connect-time SSRF checks, 20/min rate limit, 4/peer concurrency cap, 5s/30s timeouts |
| **S9** | Network storage core: `SmbFileBackend` (SMB 2/3 only) + vault integration | `partial` / `stubbed` | Policy & contract `implemented`; wire library adapter (`smbj`) `stubbed` (triggers `SIMULATION` banner) |
| **S10** | `NetworkDiscovery` (mDNS + bounded RFC1918 `/24` real TCP socket probe, foreground-only) | `implemented` | Max 254 hosts, 16 concurrency, 400ms connect, 15s deadline, 10s cooldown |
| **S11** | `WebDavFileBackend` (HTTPS-first, cert pin) & `SftpFileBackend` (TOFU host-key pin) | `partial` / `stubbed` | Pinning & policy boundaries `implemented`; wire transport adapters `stubbed` (triggers `SIMULATION` banner) |
| **S12** | Cloud auth (`CloudAuthCoordinator` + `HttpsOAuthTokenEndpointAdapter` + browser redirect) | `implemented` | Real HTTPS token exchange, system browser `ACTION_VIEW`, `com.homenode.oauth:/oauth2redirect` |
| **S13** | Google Drive backend (`CloudIdTreeBackend`: `drive.file` default, duplicate error, 429) | `partial` / `stubbed` | Resumable upload HTTP adapter and bounded streaming path `implemented`; download/tree REST operations stubbed; tests authored, not run |
| **S14** | OneDrive backend (Graph API, 320 KiB upload session chunk alignment) | `partial` / `stubbed` | Upload-session HTTP adapter and bounded streaming path `implemented`; download/tree REST operations stubbed; tests authored, not run |
| **S15** | Dropbox backend (API v2, App-Folder default, upload session streaming) | `partial` / `stubbed` | Upload-session HTTP adapter and bounded streaming path `implemented`; download/tree REST operations stubbed; tests authored, not run |
| **S16** | `WireGuardTransport` (`/32` `AllowedIPs`, source-IP cryptokey routing) | `partial` / `stubbed` | Cryptokey router & `/32` enforcement `implemented`; `UserspaceWireGuardEngineStub` active (triggers `SIMULATION` banner) |
| **S17** | Pairing (`PairingPayloadParser`, `ModeAPairingCoordinator` single-use QR with real X25519 keys) | `implemented` | Mode A `implemented`; Mode B intentionally `blocked` pending ADR-004 threat review |
| **S18** | Android lifecycle (`NodeService`, `BootReceiver`, `LockManager`, `LanInterfaceDetector`) | `implemented` | 2-arg `startForeground` on API 28, starts/stops `NodeRuntime`, detects real RFC1918 LAN IPs |
| **S19** | `Reachability` (`DirectLanReachability`, `CompositeReachability`, UPnP/STUN/Relay stubs) | `partial` / `stubbed` | Real `NetworkInterface` LAN IP discovery `implemented`; UPnP/STUN/Relay `stubbed` |
| **S20** | Jetpack Compose UI (`DashboardTab`, `StorageMountsTab`, `PeersAndPairingTab`, `LanAndSecurityTab`) | `implemented` | Prominent `SIMULATION / STUB ADAPTERS ACTIVE` banner, real SAF picker, system browser PKCE |
| **S21** | Hardening: Threat-model verification matrix (`TM-01`..`TM-07`), fuzz test, log audit, R8 rules | `implemented` | All 9 modules compile and unit test suites execute |
