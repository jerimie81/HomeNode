# ADR-004: Pairing Mode B (PSK-Authenticated Noise Bootstrap Handshake)

- **Status:** Proposed (Mode A ships first; Mode B gated on explicit threat review)
- **Slices Gated:** S17 (Mode B portion only)

## Decision Question
What exact Noise handshake pattern (e.g. `Noise_XXpsk3` or `Noise_NNpsk0` + SAS verification), vetted library, rate-limiting, and single-use token consumption rules govern Mode B pairing over an untrusted network?

## Guardrail
Mode A (mutual out-of-band QR exchange of static public keys + node user confirmation of label and per-mount capabilities) ships first. Mode B must not be implemented until a dedicated threat review is approved by the user.
