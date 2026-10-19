# HomeNode R8 / ProGuard Hardening Rules (Slice S21)
-keepattributes *Annotation*,InnerClasses,Signature,Exceptions

# Keep BouncyCastle RFC 7748 X25519 & provider classes used for identity and tunnel cryptography
-keep class org.bouncycastle.math.ec.rfc7748.** { *; }
-dontwarn org.bouncycastle.**

# Keep foreground service and boot receiver entry points
-keep class com.homenode.service.node.NodeService { *; }
-keep class com.homenode.service.node.BootReceiver { *; }

# Strip verbose debug/trace logging in release builds (§14)
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
