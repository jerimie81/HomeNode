# ADR-003: Peer Authentication & Out-of-Tunnel Signing

- **Status:** Proposed
- **Slices Gated:** S3, S4, S17

## Decision Question
Is the static Curve25519 (X25519) WireGuard public key sufficient as the sole cryptographic peer identity (`PeerId`), or does any v1 flow require an auxiliary Ed25519 signing keypair?

## Proposed Stance
X25519 is used strictly for WireGuard Diffie-Hellman key agreement (never for signing). Because all file and LAN proxy requests run inside the mutually authenticated WireGuard tunnel, `PeerId` is the peer's X25519 public key derived from cryptokey routing (`source tunnel /32 IP ↔ public key`). No Ed25519 key is introduced in v1 unless an out-of-tunnel signed artifact is later required.
