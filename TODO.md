# HomeNode implementation handoff

## Release gate

Do not present HomeNode as a usable P2P storage node until every P0 item below is complete, tested on-device, and the simulation banners are absent in production mode. The current implementation is an explicitly labeled prototype: it has no real WireGuard engine, real SMB/WebDAV/SFTP wires, or real cloud-storage REST backend.

## P0 — repair identity, pairing, and transport binding

- [ ] Replace `HomeNodeFacade.pairNewDeviceModeA`'s locally manufactured peer with a real pairing flow.
  - [x] Removed locally generated remote-key pairing; the invitation action now only generates an invitation and cannot report a fake successful pairing.
  - [x] Added a scanned-response completion entry point that consumes the node-issued token, registers the scanned remote public key, and rolls authorization back if transport peer setup fails.
  - [x] Node issues a short-lived QR; scanned response carries the remote device public key and node-issued one-time token.
  - [x] Require explicit local confirmation of peer label and selected capabilities before registration.
  - [x] Consume token exactly once; enforce TTL and failed-attempt limits; bind identity to scanned remote public key.
  - [x] Never create a remote key locally or report successful pairing before registration.
  - [x] Register transport peer with allocated `/32`; revocation removes peer from transport.
  - [ ] Add full integration coverage for replay, expiry, token mismatch, confirmation rejection, and revocation stream teardown.

- [x] Bind the transport public identity to `NodeIdentityManager`'s persisted X25519 identity before construction/start.
  - [x] Do not construct a transport from `generateEphemeralKeypair()` during `HomeNodeFacade` initialization.
  - [x] Load or initialize identity before constructing/starting the selected transport.
  - [ ] Give a real WireGuard engine the matching protected private key without exposing it outside `CredentialVault` (blocked: no production engine exists).
  - [ ] Assert that the public key advertised in pairing QR, the peer-authorizer identity, and the WireGuard static public key are byte-for-byte identical. Runtime identity-to-transport public-key equality is covered; QR and engine equality are not.
  - Keep private key bytes inside `CredentialVault`/keystore boundaries; zero temporary buffers.

- [ ] Implement a real production transport behind `WireGuardEngine`.
  - [ ] This remains blocked: only `UserspaceWireGuardEngineStub` exists; no production engine dependency/netstack is present. Do not report production transport as implemented.
  - Complete the ADR-001 hardware spike first, choose the supported WireGuard userspace/netstack integration, and implement interface lifecycle, peer configuration, stream dialing, and inbound stream delivery.
  - Preserve strict one-peer-to-one-`/32` routing and reject wildcard `AllowedIPs`.
  - Keep `TestTransport` test-only and make production construction fail closed when the real engine is unavailable.
  - Add physical API-28-device tests: start/stop, two-peer connection, cryptokey routing rejection, stream teardown after revocation, Wi-Fi loss/recovery, and reboot recovery.

## P0 — make writes bounded and genuinely streaming

- [x] Remove full-object buffering from `CloudIdTreeBackend.write` and `SafFileBackend.write`.
  - Do not use `ByteArrayOutputStream` for peer-provided file bodies.
  - [x] Stream SAF writes to a temporary sibling document, count bytes while writing, verify `expectedSize`, enforce a 512 MiB SAF quota, then replace through provider rename with rollback. Clean up partial output on cancellation or failure.
  - [x] Stream cloud writes through provider upload sessions; emit OneDrive-compliant 320 KiB non-final chunks without assembling the object in memory. Adapters fail closed when absent.
  - [x] Replace the generic 2 GiB limit in the file service with backend-specific quotas (SAF 512 MiB; cloud provider limits; in-memory backend retains its own 2 GiB cap).
  - [x] Add tests for multi-chunk, quota rejection, cancellation, size mismatch, cleanup, and atomic replacement semantics. Tests are authored but not compiled or run.
  - [x] Add Google Drive and Dropbox append-failure cleanup tests; retry/backoff and resumable recovery for transient failures remain.
  - [x] Reject peer WRITE DATA frames larger than 64 KiB before emitting payloads to the backend/uploader.

## P0 — restore reproducible builds and test execution

- [ ] Fix the committed Gradle wrapper and isolate local tooling artifacts.
  - [x] Commit `gradlew` with executable mode `100755`; retain `gradlew.bat` as a normal Windows file.
  - [x] Wrapper targets Gradle 9.8 and wrapper script/JAR are present. `./gradlew --no-daemon help` reached configuration but stalled resolving/configuring plugins and was stopped; no clean build verification yet.
  - [ ] Align the ignored, machine-local JDK 25 daemon pin with a documented/project-supported JDK; this host has JDK 21. Do not modify or commit the ignored pin without confirming project intent.
  - [x] Add `.gitignore` rules for `.idea/`, `**/build/`, `*.zip`, extracted Gradle distributions, logs, and other machine-local files. Keep only deliberate shared IDE configuration if explicitly approved.
  - [ ] Validate from a clean checkout: `./gradlew --no-daemon test`, debug assembly, and dependency resolution without relying on untracked files.

## P1 — lifecycle, persistence, and network hardening

- [ ] Make the foreground service compatible with the target SDK.
  - Declare the justified foreground-service type and required permissions for supported Android versions.
  - Use the appropriate `startForeground` overload on modern Android while retaining the API-28 path.
  - Test notification permission behavior, service-start deadlines, user stop, `START_STICKY`, boot restart, and process death.

- [ ] Persist operational state securely.
  - Persist peers, allocated tunnel addresses, mount metadata, selected capabilities, desired-running state, and non-secret configuration in encrypted or integrity-protected storage.
  - Keep passwords, private keys, OAuth refresh tokens, and other secrets solely in `CredentialVault`.
  - On restart, validate all persisted entries; fail closed for corruption, expired peers, unavailable keystore material, or removed SAF permission.
  - Add restart/reboot tests proving authorized peers retain only their intended grants and revoked peers stay revoked.

- [ ] Enforce own-interface exclusion everywhere LAN destinations are validated.
  - [x] Pass current local RFC1918 interface addresses to `LanStorageAddressPolicy.validateLanTarget` from discovery paths; discovery now filters both mDNS and probes before opening a socket.
  - [x] Pass current local RFC1918 interface addresses to `LanStorageAddressPolicy.validateLanTarget` from network-mount creation and SMB/WebDAV/SFTP connection paths.
  - Revalidate immediately before every outbound connection, not just when a destination is saved.
  - Add tests rejecting every local interface address and allowing only a different RFC1918 host.

- [ ] Make OAuth request generation and token rotation failure-safe.
  - [x] Build authorization URLs with percent-encoded query parameters.
  - [x] On refresh-token rotation, require `vault.put` success before returning success; persistence failure now clears cached access state and requires re-authentication.
  - [x] Zero cached access tokens when expired or replaced.
  - [x] Cap pending PKCE requests at eight and expire abandoned requests after five minutes, closing expired verifiers.
  - [x] Add tests for special-character client IDs and failed rotated-token persistence.
  - [x] Add a test for expired PKCE state and request-capacity recovery.
  - [ ] Add tests for cached token cleanup and zeroing.

- [ ] Tighten protocol parsing.
  - [x] Require decoders to consume all input bytes; reject trailing payload data.
  - [x] Decode UTF-8 strictly instead of replacement-decoding malformed input.
  - Add malformed/fuzz tests for trailing bytes, invalid UTF-8, oversized field lengths, and request-ID interleaving during writes.

## P1 — replace remaining simulated storage paths

- [ ] Implement actual SMB, WebDAV, SFTP, and cloud REST adapters, or keep them inaccessible from production UI until implemented.
  - Preserve SMB dialect/signing/encryption checks, WebDAV HTTPS/certificate pinning, SFTP host-key pinning, and the LAN target policy at connection time.
  - Ensure the UI reflects the real adapter state, never a successful simulated mount.
  - Add integration tests against disposable local fixtures and provider sandbox accounts; do not use production credentials in tests.

## Quality gates

- [x] Remove generic example arithmetic and app-context tests; retain behavior-focused Robolectric, architecture, and module tests. Cloud upload tests are authored but not yet executed.
- [x] Expand CI to run Kotlin formatting, Android lint, unit tests, dependency lock/checksum generation, and clean debug assembly. First green run remains required.
- [ ] Check in generated dependency lockfiles and Gradle verification metadata after a successful trusted dependency-resolution run.
- [ ] Perform an Android-device validation run for API 28 and a currently supported Android version before any release candidate.
- [x] Update `STATUS.md` to distinguish implemented upload slices from unverified tests and simulated/unavailable cloud operations. ADR review remains pending where architecture decisions change.

## Implementation status — 2026-10-07

Completed in this pass:

- `gradlew` is executable and generated IDE/build/tooling artifacts are ignored.
- OAuth authorization parameters are percent-encoded; rotated refresh-token persistence now fails closed; expired/replaced cached access tokens are zeroed.
- Protocol payload decoders reject trailing bytes and malformed UTF-8.
- LAN discovery excludes the node's current RFC1918 addresses before mDNS results are returned or TCP probes are opened.
- The façade no longer fabricates a remote pairing key. It now exposes `completePairingFromScannedResponse`, which requires a remotely scanned response and rolls authorization back if transport peer configuration fails.
- SAF writes now stream to sibling staging documents and commit after size verification; replacement uses provider rename with rollback and cleans up failed staging files.
- Cloud writes now use OneDrive, Google Drive, or Dropbox upload sessions through a bounded chunk buffer and production HTTP transport. `CloudIdTreeBackend` no longer retains uploaded bodies; it installs item metadata after provider commit. Cloud download/read and remote tree metadata operations remain simulated or unavailable.
- Pending OAuth PKCE requests are capped at eight and expire after five minutes; expired verifiers are closed.
- Transport construction now waits for the persisted identity and verifies the transport public key; real WireGuard private-key binding remains blocked on the engine implementation.

Verification completed:

- `git diff --check` passes.
- `test -x gradlew` passes.

Cloud upload follow-up: provider tests and backend integration tests are authored but not run because no Kotlin/Gradle toolchain is available in this environment. Next target is real cloud list/read/stat/mkdir/delete/move and persisted remote metadata; keep production capability claims gated until compilation, tests, and provider sandbox validation pass.

Test blocker to resolve before claiming test success:

- `bash gradlew --no-daemon test` reads the untracked `gradle/gradle-daemon-jvm.properties`, requests JDK 25 through Foojay, and fails because this host has JDK 21 and the configured Foojay URL returns HTTP 400. Do not delete or overwrite that local file without confirming the intended project JDK; either install/pin a valid JDK 25 toolchain or remove the generated daemon-JVM requirement and validate the declared wrapper/AGP combination from a clean checkout.

Latest implementation slice:

- Transport creation is deferred until `NodeRuntime` loads the persisted node identity; the selected transport is checked against that identity before startup. The transport factory is idempotent across stop/start cycles.
- The pairing QR and runtime snapshot use the same loaded `NodePublicIdentity`; the transport now exposes its matching public key. Private key bytes remain managed by `CredentialVault`.
- A runtime behavior test now verifies the persisted identity matches the transport public key across start and restart. Pairing-QR equality is not separately asserted, and this does not configure a WireGuard engine with private key material; the engine remains unavailable.

Next implementation target:

- Remove whole-object buffering from `CloudIdTreeBackend.write` using provider upload sessions. Keep the production release gate closed until real transport and storage adapters are implemented and validated.
