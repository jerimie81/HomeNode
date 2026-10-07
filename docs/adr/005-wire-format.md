# ADR-005: File Protocol v2 Wire Format (Protobuf vs CBOR)

- **Status:** Proposed
- **Slices Gated:** S5 (`FileService` & Frame Codec)

## Decision Question
Should the length-prefixed frame payload (`| len:u32 | type:u8 | flags:u8 | requestId:u32 | payload |`) on tunnel port 7001 encode control messages (`HELLO`, `LIST`, `STAT`, `READ`, `WRITE`, `MKDIR`, `DELETE`, `MOVE`, `CANCEL`, `OK`, `ERROR`) using **Protobuf Lite (`protobuf-javalite` / `protobuf-kotlin-lite`)** or **CBOR** (or a strict zero-reflection manual binary codec for the fixed message set)?

## Constraints
No Java `Serializable` or arbitrary reflection-based deserialization on network input. Must enforce pre-allocation size bounds (`MAX_FRAME = 1 MiB`).
