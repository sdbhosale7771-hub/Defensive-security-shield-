package com.example.antispyware.hardening

import android.app.Activity
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.WindowManager
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/*
 * 1. Release Build Obfuscation (add to app/build.gradle.kts):
 *
 * buildTypes {
 *     release {
 *         isMinifyEnabled = true
 *         isShrinkResources = true
 *         proguardFiles(
 *             getDefaultProguardFile("proguard-android-optimize.txt"),
 *             "proguard-rules.pro"
 *         )
 *     }
 * }
 *
 * 2. Also set android:allowBackup="false" in AndroidManifest.xml <application>
 *    so ADB backup cannot extract local app data.
 */

/**
 * 1. ScreenCaptureGuard
 * Blocks screenshots and screen recording on sensitive security screens.
 */
object ScreenCaptureGuard {
    fun enableSecureWindow(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}

/**
 * 2. SecureKeystoreCrypto
 * Uses AndroidKeyStore (AES-256-GCM) so encryption keys never leave secure hardware.
 */
object SecureKeystoreCrypto {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "DefensiveAppMasterKey"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existingKey = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existingKey != null) return existingKey

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    fun encrypt(plainText: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        val iv = cipher.iv
        val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        val combined = ByteArray(iv.size + cipherBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(cipherBytes, 0, combined, iv.size, cipherBytes.size)
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decrypt(encryptedBase64: String): String {
        val combined = Base64.decode(encryptedBase64, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, 12)
        val cipherBytes = combined.copyOfRange(12, combined.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(cipherBytes), Charsets.UTF_8)
    }
}

/**
 * 3. AppIntegrityGuard
 * Detects APK re-signing/tampering, attached debuggers, and basic root indicators.
 * For production apps, pair this with Google Play Integrity API server-side verification.
 */
data class IntegrityStatus(
    val isSignatureValid: Boolean,
    val isDebuggerAttached: Boolean,
    val isRootIndicatorFound: Boolean
) {
    val isEnvironmentSafe: Boolean
        get() = isSignatureValid && !isDebuggerAttached && !isRootIndicatorFound
}

object AppIntegrityGuard {

    // Replace with your actual Release Keystore SHA-256 (uppercase hex, no colons)
    private const val EXPECTED_RELEASE_SHA256 = "YOUR_RELEASE_CERT_SHA256_HEX"

    fun checkIntegrity(context: Context): IntegrityStatus {
        return IntegrityStatus(
            isSignatureValid = verifySigningCertificate(context),
            isDebuggerAttached = isDebuggerPresent(context),
            isRootIndicatorFound = hasBasicRootIndicators()
        )
    }

    private fun isDebuggerPresent(context: Context): Boolean {
        val isDebuggableFlag = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger() || isDebuggableFlag
    }

    private fun verifySigningCertificate(context: Context): Boolean {
        if (EXPECTED_RELEASE_SHA256 == "YOUR_RELEASE_CERT_SHA256_HEX") {
            // Skip strict check until developer configures their release SHA-256
            return true
        }
        return try {
            val pm = context.packageManager
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                info.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
            } ?: return false

            signatures.any { sig ->
                val digest = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
                val hex = digest.joinToString("") { "%02X".format(it) }
                hex == EXPECTED_RELEASE_SHA256
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun hasBasicRootIndicators(): Boolean {
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) return true

        val commonSuPaths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su"
        )
        return commonSuPaths.any { File(it).exists() }
    }
}
