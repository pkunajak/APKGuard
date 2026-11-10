# apk-parser (used reflectively by its own internals)
-dontwarn net.dongliu.**
-keep class net.dongliu.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class com.apkguard.app.**$$serializer { *; }
-keepclasseswithmembers class com.apkguard.app.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Retrofit / OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn retrofit2.**
-if interface * { @retrofit2.http.* <methods>; }
-keep,allowobfuscation interface <1>
