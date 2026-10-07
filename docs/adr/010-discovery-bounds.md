# ADR-010: LAN Storage Discovery Scope & Active Probe Limits

- **Status:** Proposed
- **Slices Gated:** S10 (`NetworkDiscovery`)

## Decision Question
What exact bounds govern `NetworkDiscovery` when the user presses "Scan" in the foreground UI?
- **Passive/mDNS:** `NsdManager` queries for `_smb._tcp`, `_webdavs._tcp`, `_webdav._tcp`, `_sftp-ssh._tcp` on the active Wi-Fi interface (`WifiManager.MulticastLock` held only during scan window, max 15s).
- **Active TCP Subnet Probe:** Restricted strictly to the active Wi-Fi interface's RFC1918 subnet, capped at `/24` (max 254 hosts), ports `[445, 22, 443, 5006]`, max concurrency `16`, per-port connect timeout `400ms`, overall scan deadline `15s`, minimum `10s` cooldown between scans. Never callable from peer/tunnel code paths.
