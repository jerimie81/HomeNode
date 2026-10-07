# ADR-001: Tunnel Engine Architecture (VpnService vs Userspace WireGuard + Netstack)

- **Status:** Proposed (Blocked on Slice T Hardware Spike)
- **Slices Gated:** S16 (`WireGuardTransport`)

## Decision Question
Should `:core-transport`'s `WireGuardTransport` use:
- **Option A:** `com.wireguard.android:tunnel` (`VpnService` / TUN device-wide tunnel), or
- **Option B:** Userspace WireGuard + embedded TCP/IP netstack (`wireguard-go` netstack or Rust `boringtun` + `smoltcp` via JNI/gomobile) exposing in-process `openStream`/`listen` without occupying Android's single `VpnService` slot?

## Key Constraints & Measurements Required (Slice T on Galaxy S8+ arm64, API 28)
1. Does Option B compile cleanly for `arm64-v8a` NDK and provide bidirectional stream sockets with authenticated source peer IP (`IncomingStream.remotePeer`)?
2. APK size delta, RSS memory overhead (must stay well within 4 GB RAM budget), CPU/thermal impact during 64 KiB chunk streaming, and idle battery drain over 1 hour on S8+.
3. Round-trip echo latency over LAN Wi-Fi between S8+ and a second peer device.
