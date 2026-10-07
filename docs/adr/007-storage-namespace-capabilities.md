# ADR-007: Unified Multi-Storage Namespace & Per-Mount Capability Model

- **Status:** Proposed
- **Slices Gated:** S1, S4, S5, S6

## Decision Question
Confirm the v2 storage namespace `/<mountId>/<relativePath>` and capability model (`Files(mountId, READ|WRITE)`):
1. Opaque random `MountId` used for routing; user labels are display-only.
2. Root `/` lists only mounts where the calling peer has `Files(mountId, READ)`.
3. Default deny on new mounts; cloud mounts are never included in batch/default grants and require an explicit warning.
4. `readOnly` flag on `StorageMount` overrides peer `WRITE` capability at the backend boundary.
5. Cross-mount `MOVE` returns `UNSUPPORTED` in v1.
