# ADR-008: Network Storage Client Libraries (SMB 2/3, SFTP, WebDAV) on API 28

- **Status:** Proposed
- **Slices Gated:** S9 (SMB), S11 (WebDAV, SFTP)

## Decision Question
Which libraries should back our `:storage-network` interfaces, and what are their Android API 28 / BouncyCastle / Conscrypt / method-count implications?
- **SMB 2/3 (never SMB1):** `com.hierynomus:smbj` (primary candidate) vs `eu.agno3.jcifs:jcifs-ng` (fallback). `// VERIFY` Android 9 provider compatibility and SMB3 encryption/signing APIs.
- **SFTP:** `com.hierynomus:sshj` with mandatory TOFU host-key pinning stored in `MountConfig`. `// VERIFY` curve25519-sha256 / ed25519 host key support on API 28.
- **WebDAV:** Minimal in-house OkHttp-based client (`PROPFIND`, `GET`, `PUT`, `MKCOL`, `DELETE`, `MOVE`) with XML pull parsing (`XmlPullParser`, disabling external entities/XXE) + optional SHA-256 certificate pin per mount.
