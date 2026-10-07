# ADR-009: Cloud OAuth 2.0 + PKCE Architecture, Scopes & Redirect Scheme

- **Status:** Proposed
- **Slices Gated:** S12, S13, S14, S15

## Decision Question
How are OAuth 2.0 + PKCE flows executed and configured for Google Drive, OneDrive, and Dropbox?
- **Library:** `net.openid:appauth` (AppAuth-Android) via Custom Tabs / system browser (never WebView), behind our `CloudAuth` interface.
- **Client IDs:** User-supplied public client IDs injected via `local.properties` / Secrets into `BuildConfig` (never client secrets).
- **Default Scopes (least privilege):**
  - Google Drive: `https://www.googleapis.com/auth/drive.file` (full `drive` / `drive.readonly` only as explicit warned per-account opt-in; note Google testing-mode 7-day refresh token expiry).
  - OneDrive: `Files.ReadWrite.AppFolder` + `offline_access` (or `Files.Read.All` / `Files.ReadWrite.All` on explicit opt-in).
  - Dropbox: `files.metadata.read`, `files.content.read`, `files.content.write` with App Folder access type default (`token_access_type=offline`).
