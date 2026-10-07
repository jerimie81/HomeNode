# ADR-011: SDK Levels (`minSdk`, `compileSdk`, `targetSdk`) & Sideload Distribution

- **Status:** Proposed (Awaiting User Confirmation in S0)
- **Slices Gated:** S0+

## Decision Question
Confirm the SDK posture for HomeNode targeting the Samsung Galaxy S8+ (Android 9 / API 28):
- **`minSdk = 26`** (Android 8.0; guarantees `java.time` and modern keystore/autofill/notification channel APIs without desugaring overhead on API 28).
- **`compileSdk = 35` (or `36` per current Android Studio template)** so modern Jetpack Compose and AndroidX libraries compile cleanly.
- **`targetSdk = 35` (or `28` vs `35` trade-off):** On an API 28 physical device, OS-enforced `targetSdk` behavioral gates above 28 are inactive at runtime, except static manifest/Play-Protect checks. We gate all API > 28 calls with `Build.VERSION.SDK_INT` checks.
- **Distribution:** Sideloaded personal APK (`assembleDebug` / signed personal `assembleRelease`).
