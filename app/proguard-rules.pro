# HomeNode R8 / ProGuard Hardening Rules (Slice S21)
-keepattributes *Annotation*,InnerClasses,Signature,Exceptions

# Strip verbose debug/trace logging in release builds (§14)
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
