# ADR-006: Foreground Service, Boot Start & Samsung Battery Policy on API 28

- **Status:** Proposed
- **Slices Gated:** S18 (`NodeService`, `BootReceiver`, `LockManager`)

## Decision Question
How should `NodeService` declare and run its foreground service across API 28 (Galaxy S8+ runtime) while compiling against modern `compileSdk`/`targetSdk`?

## Key Rules
- On API 28 (`Build.VERSION.SDK_INT < 29`), call `startForeground(id, notification)` without 3-argument `foregroundServiceType`. On API 29+/34+, gate `ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE` / `DATA_SYNC` behind `SDK_INT` checks.
- Verify `RECEIVE_BOOT_COMPLETED` → `startForegroundService` behavior on Samsung Experience / One UI 1.0 (Android 9) when `desiredState == RUNNING`.
- Document exact Samsung S8+ menu steps to exclude HomeNode from "Sleeping apps" / "Put unused apps to sleep".
