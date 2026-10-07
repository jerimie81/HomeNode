# HomeNode — Component & Slice Status

Truthfulness vocabulary: `not started · implemented · tested · partial · stubbed · blocked`.

## Slice Roadmap Status

| Slice | Scope | Status | Notes |
|---|---|---|---|
| **S0** | Multi-module bootstrap, ADRs 001–011, CI, architecture test | `implemented` | Awaiting user local build/test output to mark `tested` |
| **T** | Hardware tunnel spike checklist & harness (ADR-001) | `not started` | Parallel user-run hardware spike on Galaxy S8+ |
| **S1** | `:core-storage` & `:core-transport` contracts + contract test suites | `not started` | — |
| **S2** | `NodeRuntime` state machine, `RetryPolicy` (1→60s), safe event logger | `not started` | — |
| **S3** | Node identity, Keystore AES-256-GCM wrapping, `CredentialVault` | `not started` | — |
| **S4** | Peer registry, `PeerAuthorizer` (`Files`/`Lan` capabilities), IP allocator | `not started` | — |
| **S5** | `PathValidator` corpus/fuzz, frame codec, protocol v2, `FileService` | `not started` | — |
| **S6** | `MountManager` persistence, per-mount state/retry, capability enforcement | `not started` | — |
| **S7** | Local storage (`SafFileBackend` in `:storage-local`, microSD, containment) | `not started` | — |
| **S8** | `LanProxy` + `LanPolicy` (IP-literal, RFC1918, rate limits, socket binding) | `not started` | — |
| **S9** | Network storage core: SMB 2/3 backend + `LanPolicy` + vault integration | `not started` | — |
| **S10** | `NetworkDiscovery` (mDNS + bounded RFC1918 probe, foreground-only) | `not started` | — |
| **S11** | WebDAV (HTTPS-first, cert pinning) & SFTP (TOFU host-key pinning) | `not started` | — |
| **S12** | Cloud OAuth 2.0 + PKCE (`CloudAuth`, single-flight refresh, `NEEDS_REAUTH`) | `not started` | — |
| **S13** | Google Drive backend (`drive.file` default, ID resolution, resumable upload) | `not started` | — |
| **S14** | OneDrive backend (Graph API, 320 KiB chunk alignment) | `not started` | — |
| **S15** | Dropbox backend (API v2, app-folder default, upload sessions) | `not started` | — |
| **S16** | Real `WireGuardTransport` per ADR-001 spike decision | `not started` | Blocked on ADR-001 hardware spike |
| **S17** | Pairing (`PairingPayload` parser, Mode A QR; Mode B gated on ADR-004) | `not started` | — |
| **S18** | Android lifecycle (`NodeService`, `BootReceiver`, `LockManager`, API 28) | `not started` | — |
| **S19** | Reachability (Direct, UPnP, STUN, Relay, Composite) | `not started` | — |
| **S20** | Compose UI (Dashboard, Mounts, Discovery, Peers, Pairing, Logs, Settings) | `not started` | — |
| **S21** | Hardening, threat-model test matrix, fuzz/stress, R8, audit | `not started` | — |

## Subsystem Component Status

| Module | Component | Status | Active Stubs / Notes |
|---|---|---|---|
| `:app` | UI Scaffold & `HomeNodeApplication` | `stubbed` | `HomeNodeApplication` logs `BOOTSTRAP_STUB_ACTIVE` |
| `:service-node` | `NodeService`, `NodeRuntime`, `MountManager`, `LanProxy` | `not started` | Empty module + smoke test |
| `:service-files` | `FileService`, Frame Codec, Protocol v2 | `not started` | Empty module + smoke test |
| `:core-transport` | `Transport`, `Reachability`, `TestTransport`, `WireGuardTransport` | `not started` | Empty module + smoke test |
| `:core-identity` | Identity, `CredentialVault`, `PeerAuthorizer`, Pairing | `not started` | Empty module + smoke test |
| `:core-storage` | `FileBackend`, `SafePath`, `PathValidator`, `StorageMount` | `not started` | Empty module + smoke test |
| `:storage-local` | `SafFileBackend` | `not started` | Empty module + smoke test |
| `:storage-network` | SMB, WebDAV, SFTP, `NetworkDiscovery` | `not started` | Empty module + smoke test |
| `:storage-cloud` | `CloudAuth`, Google Drive, OneDrive, Dropbox | `not started` | Empty module + smoke test |
